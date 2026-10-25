"""Run the existing scanners against a source tree and evaluate the gate.

Scanning itself lives in ``core.services`` — this module only adapts each
scanner's native output into one common finding shape::

    {"scanner", "type", "id", "title", "severity", "file_path", "line",
     "package", "version", "fixed_version"}
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from core.gate.evaluator import GateDecision, evaluate
from core.gate.policy import GatePolicy, normalize_severity
from core.utils.logger import get_logger

logger = get_logger("gate.runner")


def _scan_supply_chain(path: str) -> list[dict]:
    from core.services.supply_chain import dependency_scanner

    return [
        {
            "scanner": "supply_chain",
            "type": "dependency",
            "id": v.get("cve_id") or v.get("id") or "",
            "title": f"{v.get('package')} {v.get('version')} - {v.get('cve_id') or v.get('id')}",
            "severity": normalize_severity(v.get("severity")),
            "file_path": v.get("manifest", ""),
            "line": 0,
            "package": v.get("package"),
            "version": v.get("version"),
            "fixed_version": v.get("fixed_version"),
        }
        for v in dependency_scanner.scan_path(path)
    ]


def _scan_security_debt(path: str) -> list[dict]:
    # scan_path only — scanner.scan_dependencies would re-run supply_chain.
    from core.services.security_debt import scanner

    return [
        {
            "scanner": "security_debt",
            "type": f.type,
            "id": f.metadata.get("detector", "") if f.metadata else "",
            "title": f.title,
            "severity": normalize_severity(f.severity),
            "file_path": f.file_path,
            "line": f.line,
            "package": None,
            "version": None,
            "fixed_version": None,
        }
        for f in scanner.scan_path(path)
    ]


def _scan_iac(path: str) -> list[dict]:
    # Trivy config + Checkov; already emits the common shape (scanner="iac").
    from core.services.iac_scan import scanner

    return scanner.scan(path)


SCANNERS: dict[str, Callable[[str], list[dict]]] = {
    "supply_chain": _scan_supply_chain,
    "security_debt": _scan_security_debt,
    "iac": _scan_iac,
}


@dataclass
class GateResult:
    decision: GateDecision
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.decision.passed


def run_gate(path: str | Path, policy: GatePolicy) -> GateResult:
    """Scan ``path`` with ``policy.scanners`` and evaluate the result.

    A scanner that raises (or an unknown scanner name) is recorded in
    ``errors``; whether that blocks is decided by ``policy.fail_open``.
    """
    path = str(path)
    findings: list[dict] = []
    errors: list[str] = []
    ran: list[str] = []

    if not Path(path).is_dir():
        errors.append(f"scan path not found: {path}")
    else:
        for name in policy.scanners:
            fn = SCANNERS.get(name)
            if fn is None:
                errors.append(f"unknown scanner '{name}'")
                continue
            try:
                findings += fn(path)
                ran.append(name)
            except Exception as exc:  # noqa: BLE001 - recorded, honoured via fail_open
                logger.warning("gate scanner %s failed on %s: %s", name, path, exc)
                errors.append(f"scanner '{name}' failed: {exc}")

    decision = evaluate(findings, policy, errors)
    logger.info(
        "gate on %s: %s (%d findings, %d blocking, %d errors)",
        path, decision.decision, len(findings), len(decision.blocking), len(errors),
    )
    return GateResult(decision=decision, findings=findings, errors=errors, scanners_run=ran)
