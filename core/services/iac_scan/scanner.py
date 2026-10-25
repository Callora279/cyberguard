"""IaC scanner entrypoints: Trivy config + Checkov over a tree, Trivy over images."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from core.services.iac_scan import checkov_runner, trivy_runner
from core.utils.logger import get_logger

logger = get_logger("iac_scan.scanner")


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f["id"], f["file_path"], f["line"], f.get("resource", ""), f.get("package"))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scan(path: str | Path) -> list[dict]:
    """Misconfigurations under ``path`` from Trivy config + Checkov, merged."""
    findings = _dedupe(trivy_runner.run_config_scan(path) + checkov_runner.run(path))
    logger.info("iac scan of %s produced %d findings", path, len(findings))
    return findings


def scan_images(refs: Iterable[str]) -> list[dict]:
    """OS + library CVEs for each container image ref."""
    findings: list[dict] = []
    for ref in refs:
        findings += trivy_runner.run_image_scan(ref)
    return _dedupe(findings)
