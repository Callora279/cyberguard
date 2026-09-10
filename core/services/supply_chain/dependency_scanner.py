"""Parse dependency manifests and check them against OSV / NVD / GH Advisories."""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("supply_chain.dependency_scanner")

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


def query_osv(ecosystem: str, name: str, version: str) -> list[dict]:
    """Query the OSV.dev API for a single package version."""
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
            m = re.search(r"/AV:.*", sev.get("score", ""))
            cvss = max(cvss, _cvss_from_vector(sev.get("score", "")))
        db_specific = v.get("database_specific", {}) or {}
        fixed = _extract_fixed_version(v)
        out.append(
            {
                "id": v.get("id"),
                "package": name,
                "version": version,
                "ecosystem": ecosystem,
                "summary": v.get("summary") or v.get("details", "")[:200],
                "cvss": round(cvss, 1),
                "severity": db_specific.get("severity", "").lower() or _severity_from_cvss(cvss),
                "fixed_version": fixed,
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


def scan_path(root: str | Path) -> list[dict]:
    """Full scan: discover manifests, parse, query OSV, return flat vuln list."""
    results: list[dict] = []
    for manifest in discover_manifests(root):
        rel = str(manifest)
        for dep in parse_manifest(manifest):
            for vuln in query_osv(dep["ecosystem"], dep["name"], dep["version"]):
                vuln["manifest"] = rel
                vuln["direct"] = dep["direct"]
                results.append(vuln)
    logger.info("dependency scan found %d vulnerable components", len(results))
    return results
