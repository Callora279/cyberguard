"""Map a Fingerprint to gate-shaped findings by running the version detectors.

Output matches core.gate.runner's common finding shape, so livescan findings
flow through the same evaluator, CLI and risk score as every other scanner.
Extra keys (target, cvss, status, confidence, remediation, caveat) are ignored
by the gate and surfaced in livescan's own reports."""
from __future__ import annotations

from urllib.parse import urlparse

from core.services.livescan.fingerprint import Fingerprint
from core.services.livescan.detectors import php2shell


def _host(url: str) -> str:
    return urlparse(url).netloc or url


def _php_fixed_version(ver: str | None) -> str | None:
    try:
        a, b, _ = (int(x) for x in (ver or "").split(".")[:3])
    except (ValueError, AttributeError):
        return None
    patch = php2shell.FIXED.get((a, b))
    return f"{a}.{b}.{patch}" if patch else None  # EOL branches: no fixed release


def match(fp: Fingerprint) -> list[dict]:
    """Run every version detector against the fingerprint; return gate findings."""
    host = _host(fp.target_url)
    findings: list[dict] = []

    php = php2shell.check(fp.php_version)
    if php:
        findings.append({
            "scanner": "livescan",
            "type": "live-cve",
            "id": ", ".join(php["cves"]),
            "title": f"PHP {php['php_version']} — PHP2Shell ({'/'.join(php['cves'])})",
            "severity": php["severity"],
            "file_path": host,          # gate's location field = the host, for livescan
            "line": 0,
            "package": "php",
            "version": php["php_version"],
            "fixed_version": _php_fixed_version(php["php_version"]),
            "target": fp.target_url,
            "cvss": php["cvss"],
            "status": php["status"],
            "confidence": php["confidence"],
            "remediation": php["remediation"],
            "caveat": php["caveat"],
        })
    # Future server/framework detectors (nginx, apache) register here the same way.
    return findings
