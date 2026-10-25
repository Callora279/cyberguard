"""CI entrypoint for the security gate.

    python -m core.gate.cli --path . [--fail-on critical] [--scanners supply_chain,security_debt]

Exits 0 when the gate passes, 1 when it blocks (or a scan errors, unless
``--fail-open``), 2 on bad arguments.
"""
from __future__ import annotations

import argparse
import sys

from core.gate.policy import DEFAULT_SCANNERS, SEVERITY_ORDER, GatePolicy
from core.gate.runner import run_gate

_MAX_LISTED = 50


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m core.gate.cli", description="CyberGuard security gate")
    p.add_argument("--path", default=".", help="source tree to scan (default: .)")
    p.add_argument("--fail-on", default="critical", choices=SEVERITY_ORDER, help="blocking severity threshold")
    p.add_argument("--scanners", default=",".join(DEFAULT_SCANNERS), help="comma-separated scanner list")
    p.add_argument("--fail-open", action="store_true", help="pass (with a warning) if a scanner errors")
    args = p.parse_args(argv)

    policy = GatePolicy(
        fail_on=args.fail_on,
        scanners=[s for s in args.scanners.split(",") if s.strip()],
        fail_open=args.fail_open,
    )
    result = run_gate(args.path, policy)
    d = result.decision

    print(f"CyberGuard security gate — {args.path} (fail on: {policy.fail_on})")
    print("  " + "  ".join(f"{s}: {d.summary.get(s, 0)}" for s in SEVERITY_ORDER))
    for reason in d.reasons:
        print(f"  - {reason}")

    if d.blocking:
        print(f"\nBlocking findings ({len(d.blocking)}):")
        for f in d.blocking[:_MAX_LISTED]:
            loc = f"{f['file_path']}:{f['line']}" if f.get("line") else (f.get("file_path") or "-")
            fix = f" (fix: {f['fixed_version']})" if f.get("fixed_version") else ""
            print(f"  [{f['severity'].upper()}] {f['scanner']}: {f['title']} — {loc}{fix}")
        if len(d.blocking) > _MAX_LISTED:
            print(f"  …and {len(d.blocking) - _MAX_LISTED} more")

    print(f"\nResult: {'PASSED' if d.passed else 'BLOCKED'} ({d.short_description()})")
    return 0 if d.passed else 1


if __name__ == "__main__":
    sys.exit(main())
