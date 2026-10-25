"""Map Trivy / Checkov output into the security gate's common finding shape.

Same keys as ``core.gate.runner`` (``scanner``, ``type``, ``id``, ``title``,
``severity``, ``file_path``, ``line``, ``package``, ``version``,
``fixed_version``) plus two optional IaC extras the gate ignores:
``resource`` (e.g. ``aws_s3_bucket.logs``) and ``guidance`` (how to fix).
Severities go through the gate's ``normalize_severity`` (Trivy UNKNOWN -> info).
"""
from __future__ import annotations

from core.gate.policy import normalize_severity

SCANNER = "iac"
# Open-source Checkov only reports severities with a Prisma Cloud API key; a
# failed check with no severity is treated as medium rather than ignored.
CHECKOV_DEFAULT_SEVERITY = "medium"


def _finding(
    *,
    type: str,  # noqa: A002 - mirrors the gate's key
    rule_id: str,
    title: str,
    severity: str | None,
    file_path: str,
    line: int,
    resource: str = "",
    guidance: str = "",
    package: str | None = None,
    version: str | None = None,
    fixed_version: str | None = None,
) -> dict:
    return {
        "scanner": SCANNER,
        "type": type,
        "id": rule_id or "",
        "title": title or rule_id or "IaC finding",
        "severity": normalize_severity(severity),
        "file_path": file_path or "",
        "line": int(line or 0),
        "package": package,
        "version": version,
        "fixed_version": fixed_version,
        "resource": resource or "",
        "guidance": guidance or "",
    }


def from_trivy_config(report: dict | None) -> list[dict]:
    out: list[dict] = []
    for result in (report or {}).get("Results") or []:
        target = result.get("Target", "")
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            out.append(
                _finding(
                    type="misconfig",
                    rule_id=m.get("AVDID") or m.get("ID") or "",
                    title=m.get("Title") or m.get("Message") or "",
                    severity=m.get("Severity"),
                    file_path=target,
                    line=cause.get("StartLine") or 0,
                    resource=cause.get("Resource") or "",
                    guidance=" ".join(p for p in (m.get("Resolution"), m.get("PrimaryURL")) if p),
                )
            )
    return out


def from_trivy_image(report: dict | None, image_ref: str = "") -> list[dict]:
    out: list[dict] = []
    image = image_ref or (report or {}).get("ArtifactName", "")
    for result in (report or {}).get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            pkg, ver, fixed = v.get("PkgName"), v.get("InstalledVersion"), v.get("FixedVersion")
            vid = v.get("VulnerabilityID") or ""
            out.append(
                _finding(
                    type="container_vuln",
                    rule_id=vid,
                    title=f"{pkg} {ver} - {vid}",
                    severity=v.get("Severity"),
                    file_path=result.get("Target") or image,
                    line=0,
                    resource=image,
                    guidance=(f"Upgrade {pkg} to {fixed}" if fixed else v.get("PrimaryURL") or "No fixed version published yet"),
                    package=pkg,
                    version=ver,
                    fixed_version=fixed or None,
                )
            )
    return out


def from_checkov(report: dict | list | None) -> list[dict]:
    # one framework -> a dict; several frameworks -> a list of dicts
    reports = report if isinstance(report, list) else [report]
    out: list[dict] = []
    for r in reports:
        if not isinstance(r, dict):
            continue
        for c in (r.get("results") or {}).get("failed_checks") or []:
            line_range = c.get("file_line_range") or [0]
            check_id = c.get("check_id") or ""
            out.append(
                _finding(
                    type="misconfig",
                    rule_id=check_id,
                    title=c.get("check_name") or "",
                    severity=c.get("severity") or CHECKOV_DEFAULT_SEVERITY,
                    file_path=(c.get("file_path") or "").lstrip("/"),
                    line=line_range[0] if line_range else 0,
                    resource=c.get("resource") or "",
                    guidance=c.get("guideline") or f"See Checkov policy {check_id}",
                )
            )
    return out
