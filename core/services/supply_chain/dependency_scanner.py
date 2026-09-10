"""Parse dependency manifests and check them against OSV / NVD / GH Advisories."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("supply_chain.dependency_scanner")

# small in-process cache so a scan doesn't hit NVD once per CVE per run
_NVD_CACHE: dict[str, dict | None] = {}
_PURL_ECO = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven", "RubyGems": "gem"}

_MANIFESTS = {
    "requirements.txt": "PyPI",
    "package.json": "npm",
    "Gemfile": "RubyGems",
    "pom.xml": "Maven",
    "go.mod": "Go",
}


def parse_manifest(path: Path) -> list[dict]:
    """Return ``[{ecosystem, name, version, direct}]`` for a manifest file."""
    name = path.name
    eco = _MANIFESTS.get(name)
    if not eco:
        return []
    text = path.read_text(errors="ignore")
    deps: list[dict] = []

    if name == "requirements.txt":
        for line in text.splitlines():
            line = line.split("#")[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)\s*([0-9][\w.\-]*)", line)
            if m:
                deps.append({"ecosystem": eco, "name": m.group(1), "version": m.group(2), "direct": True})
    elif name == "package.json":
        data = json.loads(text or "{}")
        for section, direct in (("dependencies", True), ("devDependencies", False)):
            for pkg, ver in (data.get(section) or {}).items():
                deps.append(
                    {"ecosystem": eco, "name": pkg, "version": re.sub(r"[^\d.]", "", ver) or "0.0.0", "direct": direct}
                )
    elif name == "go.mod":
        for m in re.finditer(r"^\s*([\w./\-]+)\s+v([\w.\-]+)", text, re.MULTILINE):
            deps.append({"ecosystem": eco, "name": m.group(1), "version": m.group(2), "direct": "require" in text})
    elif name == "Gemfile":
        for m in re.finditer(r"gem ['\"]([\w\-]+)['\"](?:,\s*['\"][~>= ]*([\d.]+)['\"])?", text):
            deps.append({"ecosystem": eco, "name": m.group(1), "version": m.group(2) or "0.0.0", "direct": True})
    elif name == "pom.xml":
        for m in re.finditer(
            r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            text,
        ):
            deps.append(
                {"ecosystem": eco, "name": f"{m.group(1)}:{m.group(2)}", "version": m.group(3), "direct": True}
            )
    return deps


def discover_manifests(root: str | Path) -> list[Path]:
    root = Path(root)
    found: list[Path] = []
    for name in _MANIFESTS:
        found.extend(
            p for p in root.rglob(name)
            if not any(x in p.parts for x in {"node_modules", ".venv", "venv"})
        )
    return found


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def query_nvd(cve_id: str) -> dict | None:
    """Fetch authoritative CVSS + description for a CVE from the NVD 2.0 API."""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]

    result: dict | None = None
    try:
        resp = httpx.get(settings.NVD_API_URL, params={"cveId": cve_id}, timeout=15.0)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", []) or []
        if vulns:
            cve = vulns[0].get("cve", {})
            metrics = cve.get("metrics", {})
            data = (
                metrics.get("cvssMetricV31")
                or metrics.get("cvssMetricV30")
                or metrics.get("cvssMetricV2")
                or [{}]
            )[0].get("cvssData", {})
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            score = float(data.get("baseScore", 0.0))
            result = {
                "cve_id": cve_id,
                "cvss_score": score,
                "cvss_vector": data.get("vectorString", ""),
                "severity": (data.get("baseSeverity") or _severity_from_cvss(score)).lower(),
                "description": desc[:400],
            }
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.warning("NVD lookup failed for %s: %s", cve_id, exc)

    _NVD_CACHE[cve_id] = result
    return result


def query_osv(
    ecosystem: str, name: str, version: str, *, enrich_nvd: bool = True
) -> list[dict]:
    """Query the OSV.dev API for a single package version (NVD-enriched)."""
    try:
        resp = httpx.post(
            settings.OSV_API_URL,
            json={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
            timeout=15.0,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulns", []) or []
    except httpx.HTTPError as exc:
        logger.warning("OSV query failed for %s@%s: %s", name, version, exc)
        return []

    out = []
    for v in vulns:
        cvss = 0.0
        for sev in v.get("severity", []) or []:
            cvss = max(cvss, _cvss_from_vector(sev.get("score", "")))
        db_specific = v.get("database_specific", {}) or {}
        fixed = _extract_fixed_version(v)

        # prefer an authoritative CVE id (OSV often files these under aliases)
        cve_id = next(
            (a for a in ([v.get("id")] + (v.get("aliases") or [])) if str(a).startswith("CVE-")),
            None,
        )
        description = v.get("summary") or v.get("details", "")[:200]
        nvd = query_nvd(cve_id) if (enrich_nvd and cve_id) else None
        if nvd:
            cvss = nvd["cvss_score"] or cvss
            description = nvd["description"] or description

        out.append(
            {
                "id": v.get("id"),
                "cve_id": cve_id,
                "package": name,
                "version": version,
                "ecosystem": ecosystem,
                "summary": description,
                "description": description,
                "cvss": round(cvss, 1),
                "cvss_score": round(cvss, 1),
                "severity": (
                    (nvd or {}).get("severity")
                    or db_specific.get("severity", "").lower()
                    or _severity_from_cvss(cvss)
                ),
                "fixed_version": fixed,
                "fix_version": fixed,
                "patch_available": bool(fixed),
                "references": [r.get("url") for r in v.get("references", [])][:5],
            }
        )
    return out


def _cvss_from_vector(vector: str) -> float:
    # very rough CVSS v3 base-ish estimate from an AV/AC/PR/UI vector string
    if not vector or "CVSS" not in vector:
        try:
            return float(vector)
        except (TypeError, ValueError):
            return 0.0
    score = 5.0
    if "AV:N" in vector:
        score += 2.0
    if "AC:L" in vector:
        score += 1.0
    if "PR:N" in vector:
        score += 1.0
    if "C:H" in vector or "I:H" in vector:
        score += 1.0
    return min(10.0, score)


def _extract_fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def scan_path(root: str | Path, *, enrich_nvd: bool = False) -> list[dict]:
    """Full scan: discover manifests, parse, query OSV, return flat vuln list.

    NVD enrichment is off by default here — a whole-repo scan can touch dozens of
    CVEs and NVD is aggressively rate-limited. The targeted manifest endpoint
    turns it on.
    """
    results: list[dict] = []
    for manifest in discover_manifests(root):
        rel = str(manifest)
        for dep in parse_manifest(manifest):
            for vuln in query_osv(dep["ecosystem"], dep["name"], dep["version"], enrich_nvd=enrich_nvd):
                vuln["manifest"] = rel
                vuln["direct"] = dep["direct"]
                results.append(vuln)
    logger.info("dependency scan found %d vulnerable components", len(results))
    return results


def to_cyclonedx(deps: list[dict], vulns: list[dict] | None = None) -> dict:
    """Build a CycloneDX 1.5 SBOM document from parsed deps + optional vulns."""
    vulns = vulns or []
    components = []
    for d in deps:
        eco = _PURL_ECO.get(d["ecosystem"], "generic")
        components.append(
            {
                "type": "library",
                "name": d["name"],
                "version": d["version"],
                "scope": "required" if d.get("direct", True) else "optional",
                "purl": f"pkg:{eco}/{d['name']}@{d['version']}",
            }
        )

    vuln_entries = []
    for v in vulns:
        ratings = []
        if v.get("cvss_score"):
            ratings.append(
                {"method": "CVSSv3", "score": v["cvss_score"], "severity": v.get("severity", "unknown")}
            )
        eco = _PURL_ECO.get(v.get("ecosystem", ""), "generic")
        vuln_entries.append(
            {
                "id": v.get("cve_id") or v.get("id"),
                "source": {"name": "NVD" if v.get("cve_id") else "OSV"},
                "ratings": ratings,
                "description": v.get("description", ""),
                "recommendation": (
                    f"Upgrade {v['package']} to {v['fix_version']}"
                    if v.get("fix_version")
                    else "No fixed version published yet."
                ),
                "affects": [{"ref": f"pkg:{eco}/{v['package']}@{v['version']}"}],
            }
        )

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "iRaTech", "name": "CyberGuard AI", "version": "0.1.0"}],
        },
        "components": components,
    }
    if vuln_entries:
        doc["vulnerabilities"] = vuln_entries
    return doc


def scan_manifest_content(filename: str, content: str) -> dict:
    """Scan a single ``package.json`` / ``requirements.txt`` (raw content).

    Returns the parsed dependencies, the OSV/NVD vulnerability list and a
    CycloneDX SBOM document.
    """
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cg-manifest-") as tmp:
        p = Path(tmp) / Path(filename).name
        p.write_text(content)
        deps = parse_manifest(p)

    vulns: list[dict] = []
    for dep in deps:
        for vuln in query_osv(dep["ecosystem"], dep["name"], dep["version"]):
            vuln["direct"] = dep["direct"]
            vulns.append(vuln)

    by_sev: dict[str, int] = {}
    for v in vulns:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1

    return {
        "manifest": Path(filename).name,
        "dependencies": deps,
        "dependency_count": len(deps),
        "vulnerabilities": vulns,
        "vulnerable_count": len({v["package"] for v in vulns}),
        "by_severity": by_sev,
        "sbom": to_cyclonedx(deps, vulns),
    }
