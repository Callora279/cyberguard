"""Parse SPDX and CycloneDX SBOMs, validate completeness, NHS compliance check."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class SBOMComponent:
    name: str
    version: str = ""
    purl: str = ""
    license: str = "NOASSERTION"
    supplier: str = ""
    hashes: dict = field(default_factory=dict)


@dataclass
class ParsedSBOM:
    format: str
    spec_version: str
    components: list[SBOMComponent]
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "format": self.format,
            "spec_version": self.spec_version,
            "component_count": len(self.components),
            "components": [c.__dict__ for c in self.components],
            "metadata": self.metadata,
        }


def detect_format(raw: str) -> str:
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        data = json.loads(raw)
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx-json"
        if "spdxVersion" in data:
            return "spdx-json"
    if "<bom" in raw and "cyclonedx" in raw.lower():
        return "cyclonedx-xml"
    if "SPDXVersion:" in raw:
        return "spdx-tag"
    raise ValueError("unrecognised SBOM format")


def parse(raw: str) -> ParsedSBOM:
    fmt = detect_format(raw)
    if fmt == "cyclonedx-json":
        return _parse_cyclonedx_json(json.loads(raw))
    if fmt == "spdx-json":
        return _parse_spdx_json(json.loads(raw))
    if fmt == "cyclonedx-xml":
        return _parse_cyclonedx_xml(raw)
    return _parse_spdx_tag(raw)


def _parse_cyclonedx_json(data: dict) -> ParsedSBOM:
    comps = [
        SBOMComponent(
            name=c.get("name", ""),
            version=c.get("version", ""),
            purl=c.get("purl", ""),
            license=_cdx_license(c),
            supplier=(c.get("supplier") or {}).get("name", ""),
            hashes={h["alg"]: h["content"] for h in c.get("hashes", [])},
        )
        for c in data.get("components", [])
    ]
    return ParsedSBOM("CycloneDX", str(data.get("specVersion", "")), comps, data.get("metadata", {}))


def _cdx_license(c: dict) -> str:
    for lic in c.get("licenses", []):
        if "license" in lic:
            return lic["license"].get("id") or lic["license"].get("name", "NOASSERTION")
        if "expression" in lic:
            return lic["expression"]
    return "NOASSERTION"


def _parse_spdx_json(data: dict) -> ParsedSBOM:
    comps = [
        SBOMComponent(
            name=p.get("name", ""),
            version=p.get("versionInfo", ""),
            license=p.get("licenseConcluded") or p.get("licenseDeclared", "NOASSERTION"),
            supplier=p.get("supplier", ""),
        )
        for p in data.get("packages", [])
    ]
    return ParsedSBOM("SPDX", data.get("spdxVersion", ""), comps, data.get("creationInfo", {}))


def _parse_spdx_tag(raw: str) -> ParsedSBOM:
    comps: list[SBOMComponent] = []
    current: dict = {}
    for line in raw.splitlines():
        if line.startswith("PackageName:"):
            if current:
                comps.append(SBOMComponent(**current))
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("PackageVersion:"):
            current["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("PackageLicenseConcluded:"):
            current["license"] = line.split(":", 1)[1].strip()
    if current:
        comps.append(SBOMComponent(**current))
    version = next((l.split(":", 1)[1].strip() for l in raw.splitlines() if l.startswith("SPDXVersion:")), "")
    return ParsedSBOM("SPDX", version, comps)


def _parse_cyclonedx_xml(raw: str) -> ParsedSBOM:
    root = ET.fromstring(raw)
    ns = {"c": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    comps = []
    for comp in root.iter("{*}component"):
        name = comp.findtext("{*}name", default="")
        comps.append(
            SBOMComponent(
                name=name,
                version=comp.findtext("{*}version", default=""),
                purl=comp.findtext("{*}purl", default=""),
            )
        )
    return ParsedSBOM("CycloneDX", root.attrib.get("specVersion", ""), comps)


def validate_completeness(sbom: ParsedSBOM) -> dict:
    """Score how complete the SBOM is (NTIA minimum-elements style)."""
    total = len(sbom.components) or 1
    with_version = sum(1 for c in sbom.components if c.version)
    with_license = sum(1 for c in sbom.components if c.license not in ("", "NOASSERTION", "NONE"))
    with_supplier = sum(1 for c in sbom.components if c.supplier)
    with_id = sum(1 for c in sbom.components if c.purl or c.hashes)

    checks = {
        "has_components": total > 0,
        "versions_present_pct": round(with_version / total * 100, 1),
        "licenses_present_pct": round(with_license / total * 100, 1),
        "suppliers_present_pct": round(with_supplier / total * 100, 1),
        "identifiers_present_pct": round(with_id / total * 100, 1),
    }
    completeness = round(
        (checks["versions_present_pct"] + checks["licenses_present_pct"]
         + checks["suppliers_present_pct"] + checks["identifiers_present_pct"]) / 4,
        1,
    )
    return {"completeness_score": completeness, "checks": checks}


def nhs_compliance_check(sbom: ParsedSBOM) -> dict:
    """NHS England SBOM guidance: machine-readable, versioned, licensed, identified."""
    comp = validate_completeness(sbom)
    passed = (
        sbom.format in ("SPDX", "CycloneDX")
        and comp["checks"]["versions_present_pct"] >= 95
        and comp["checks"]["identifiers_present_pct"] >= 90
        and comp["checks"]["licenses_present_pct"] >= 80
    )
    return {
        "compliant": passed,
        "standard": "NHS England SBOM guidance / NTIA minimum elements",
        "completeness": comp,
        "gaps": [] if passed else _nhs_gaps(comp["checks"]),
    }


def _nhs_gaps(checks: dict) -> list[str]:
    gaps = []
    if checks["versions_present_pct"] < 95:
        gaps.append("component versions missing")
    if checks["identifiers_present_pct"] < 90:
        gaps.append("unique identifiers (purl/hash) missing")
    if checks["licenses_present_pct"] < 80:
        gaps.append("license information incomplete")
    return gaps
