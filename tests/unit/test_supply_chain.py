from pathlib import Path

from core.services.supply_chain import sbom_parser, vendor_risk
from core.services.supply_chain.dependency_scanner import parse_manifest


def test_parse_requirements(tmp_path: Path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.19.1\n# comment\nflask>=2.0.0\n")
    deps = parse_manifest(f)
    names = {d["name"] for d in deps}
    assert {"requests", "flask"} <= names


def test_parse_package_json(tmp_path: Path):
    f = tmp_path / "package.json"
    f.write_text('{"dependencies": {"lodash": "^4.17.19"}, "devDependencies": {"jest": "29.0.0"}}')
    deps = parse_manifest(f)
    assert any(d["name"] == "lodash" and d["direct"] for d in deps)
    assert any(d["name"] == "jest" and not d["direct"] for d in deps)


def test_cyclonedx_parse_and_completeness():
    raw = """{
      "bomFormat": "CycloneDX", "specVersion": "1.5",
      "components": [
        {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
         "licenses": [{"license": {"id": "MIT"}}], "supplier": {"name": "npm"}}
      ]
    }"""
    parsed = sbom_parser.parse(raw)
    assert parsed.format == "CycloneDX"
    assert parsed.components[0].name == "left-pad"
    comp = sbom_parser.validate_completeness(parsed)
    assert comp["completeness_score"] == 100.0


def test_license_risk():
    score, reason = vendor_risk.license_risk("GPL-3.0")
    assert score >= 50
    score2, _ = vendor_risk.license_risk("MIT")
    assert score2 < 20
