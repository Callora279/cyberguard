"""Standalone IaC / container scan.

    python -m core.services.iac_scan.cli --path . [--image <ref> ...] [--fail-on high]

Prints a severity summary and the blocking findings; exits 1 if anything is at
or above ``--fail-on`` (default ``high``, i.e. critical/high), else 0.
"""
from __future__ import annotations

import argparse
import sys

from core.gate.evaluator import evaluate
from core.gate.policy import SEVERITY_ORDER, GatePolicy
from core.services.iac_scan import scanner

_MAX_LISTED = 50


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m core.services.iac_scan.cli", description="CyberGuard IaC scan")
    p.add_argument("--path", default=".", help="tree with Dockerfiles / compose / k8s / Terraform (default: .)")
    p.add_argument("--image", action="append", default=[], help="container image ref to scan (repeatable)")
    p.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER, help="blocking severity threshold")
    args = p.parse_args(argv)

    findings = scanner.scan(args.path) + scanner.scan_images(args.image)
    d = evaluate(findings, GatePolicy(fail_on=args.fail_on, scanners=["iac"]))

    targets = ", ".join([args.path, *args.image])
    print(f"CyberGuard IaC scan — {targets} (fail on: {args.fail_on})")
    print("  " + "  ".join(f"{s}: {d.summary.get(s, 0)}" for s in SEVERITY_ORDER))
    if d.blocking:
        print(f"\nBlocking findings ({len(d.blocking)}):")
        for f in d.blocking[:_MAX_LISTED]:
            loc = f"{f['file_path']}:{f['line']}" if f.get("line") else (f.get("file_path") or "-")
            res = f" [{f['resource']}]" if f.get("resource") else ""
            print(f"  [{f['severity'].upper()}] {f['id']}: {f['title']} — {loc}{res}")
            if f.get("guidance"):
                print(f"      fix: {f['guidance']}")
        if len(d.blocking) > _MAX_LISTED:
            print(f"  …and {len(d.blocking) - _MAX_LISTED} more")

    print(f"\nResult: {'PASSED' if d.passed else 'BLOCKED'} ({d.short_description()})")
    return 0 if d.passed else 1


if __name__ == "__main__":
    sys.exit(main())
