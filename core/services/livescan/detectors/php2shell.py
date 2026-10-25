"""PHP2Shell (CVE-2026-109618 / CVE-2026-109619) version detector.
Pure version comparison against the published fixed releases. Sends no
payloads, never touches the session upload-progress path. Status is never
stronger than 'vulnerable-version'."""
from __future__ import annotations

CVES = ["CVE-2026-109618", "CVE-2026-109619"]
CVSS = 9.2  # v4.0, both
FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}  # branch -> first fixed patch

REMEDIATION = (
    "Upgrade to the branch's fixed release (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 "
    "or later). Interim mitigation: set session.upload_progress.enabled=0 "
    "(and on 8.5 fatal_error_backtraces=0) in php.ini, the FPM pool or server "
    "config — not ini_set() or .user.ini — then restart every PHP worker."
)
CAVEAT = (
    "Version-based detection from HTTP headers. Distros backport fixes without "
    "changing the version string, so confirm against the OS/distro CVE tracker; "
    "a Server header may also be suppressed or spoofed."
)

def _parse(ver):
    try:
        a, b, c = (int(x) for x in ver.split(".")[:3])
        return a, b, c
    except (ValueError, AttributeError):
        return None

def check(php_version: str | None) -> dict | None:
    """Finding dict if the version is affected, else None."""
    parsed = _parse(php_version) if php_version else None
    if not parsed:
        return None
    major, minor, patch = parsed
    branch = (major, minor)
    if branch in FIXED:
        if patch >= FIXED[branch]:
            return None                       # patched release
        confidence = "medium"
    elif branch <= (8, 1) or major < 8:
        confidence = "low"                    # EOL, no fix, unverifiable
    else:
        return None                           # unknown future branch — don't guess
    return {
        "detector": "php2shell",
        "php_version": php_version,
        "cves": CVES, "cvss": CVSS, "severity": "critical",
        "status": "vulnerable-version",       # never "confirmed-rce"
        "confidence": confidence,
        "remediation": REMEDIATION, "caveat": CAVEAT,
    }
