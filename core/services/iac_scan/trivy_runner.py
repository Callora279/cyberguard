"""Thin subprocess wrapper around the ``trivy`` CLI.

A missing binary, a non-zero exit or unparseable output is logged and yields
``[]`` — the IaC scanner must never take the security gate down with it.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from core.services.iac_scan import normalizer
from core.utils.logger import get_logger

logger = get_logger("iac_scan.trivy")

CONFIG_TIMEOUT = 300
IMAGE_TIMEOUT = 600  # first run downloads the vulnerability DB


def _trivy(args: list[str], timeout: int) -> dict | None:
    exe = shutil.which("trivy")
    if not exe:
        logger.warning("trivy not found on PATH; skipping 'trivy %s'", args[0])
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [exe, *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("trivy %s failed to run: %s", args[0], exc)
        return None
    if proc.returncode != 0:
        logger.warning("trivy %s exited %d: %s", args[0], proc.returncode, (proc.stderr or "").strip()[-300:])
        return None
    try:
        report = json.loads(proc.stdout or "{}")
    except ValueError as exc:
        logger.warning("trivy %s produced invalid JSON: %s", args[0], exc)
        return None
    return report if isinstance(report, dict) else None


def run_config_scan(path: str | Path) -> list[dict]:
    """Misconfigurations in Dockerfiles, compose, k8s manifests and Terraform."""
    report = _trivy(["config", "--quiet", "--format", "json", "--", str(path)], CONFIG_TIMEOUT)
    return normalizer.from_trivy_config(report) if report else []


def run_image_scan(image_ref: str) -> list[dict]:
    """OS-package + language-library CVEs in a container image."""
    if not image_ref or image_ref.startswith("-"):
        logger.warning("refusing to scan suspicious image ref %r", image_ref)
        return []
    report = _trivy(["image", "--quiet", "--format", "json", "--", image_ref], IMAGE_TIMEOUT)
    return normalizer.from_trivy_image(report, image_ref) if report else []
