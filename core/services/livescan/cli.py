"""LiveScan CLI:

    python -m core.services.livescan.cli --target https://host --org <org_id>

Read-only. Fingerprints an *authorised* target and reports version-based CVE
findings. Refuses politely if the target isn't authorised for the org."""
from __future__ import annotations

import argparse
import asyncio
import sys

from core.gate.policy import SEVERITY_ORDER
from core.services.livescan.authorization import NotAuthorizedError
from core.services.livescan.scanner import scan_target
from core.utils.exceptions import ValidationError


def _run(org_id: str, target: str) -> int:
    try:
        result = asyncio.run(scan_target(org_id, target))
    except NotAuthorizedError as exc:
        print(f"Refused: {exc}")
        print("Register and attest the target first (register_target / POST /livescan/targets).")
        return 1
    except ValidationError as exc:
        print(f"Invalid target: {exc}")
        return 2

    fp = result.fingerprint
    print(f"LiveScan — {result.target}")
    if not result.reachable:
        print("  target not reachable (no response)")
        return 1
    print(f"  server: {fp.get('server') or '-'}   x-powered-by: {fp.get('powered_by') or '-'}")
    detected = ", ".join(
        f"{name} {fp[key]}" for name, key in
        (("PHP", "php_version"), ("nginx", "nginx_version"), ("Apache", "apache_version"))
        if fp.get(key)
    )
    print(f"  detected: {detected or 'no versioned components in headers'}")
    print("  " + "  ".join(f"{s}: {result.counts.get(s, 0)}" for s in SEVERITY_ORDER))

    if result.findings:
        print(f"\nFindings ({len(result.findings)}):")
        for f in result.findings:
            print(f"  [{f['severity'].upper()}] {f['title']}  ({f.get('confidence', '-')} confidence)")
            print(f"      fix: {f.get('fixed_version') or 'no fixed release (EOL) — migrate branch'}")
            if f.get("caveat"):
                print(f"      note: {f['caveat']}")
        return 1

    print("\nNo version-based CVEs matched.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m core.services.livescan.cli", description="CyberGuard LiveScan")
    p.add_argument("--target", required=True, help="https URL of an authorised target")
    p.add_argument("--org", required=True, help="organisation id")
    args = p.parse_args(argv)
    return _run(args.org, args.target)


if __name__ == "__main__":
    sys.exit(main())
