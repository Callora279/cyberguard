"""Thin subprocess wrapper around the ``checkov`` CLI.

Same contract as :mod:`trivy_runner`: any failure is logged and yields ``[]``.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from core.services.iac_scan import normalizer
from core.utils.logger import get_logger

logger = get_logger("iac_scan.checkov")

TIMEOUT = 300
# checkov exits 1 whenever a check fails, so 1 is a normal "found issues" result.
_OK_CODES = (0, 1)


def run(path: str | Path) -> list[dict]:
    """Failed Checkov checks under ``path`` in the gate's finding shape."""
    exe = shutil.which("checkov")
    if not exe:
        logger.warning("checkov not found on PATH; skipping IaC policy checks")
        return []
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [exe, "-d", str(path), "-o", "json", "--compact"],
            capture_output=True, text=True, timeout=TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("checkov failed to run: %s", exc)
        return []
    if proc.returncode not in _OK_CODES:
        logger.warning("checkov exited %d: %s", proc.returncode, (proc.stderr or "").strip()[-300:])
        return []
    try:
        report = json.loads(proc.stdout or "[]")
    except ValueError as exc:
        logger.warning("checkov produced invalid JSON: %s", exc)
        return []
    return normalizer.from_checkov(report)
