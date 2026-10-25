"""Turn aggregated findings (+ any scanner errors) into a pass/block decision."""
from __future__ import annotations

from dataclasses import dataclass, field

from core.gate.policy import SEVERITY_ORDER, SEVERITY_RANK, GatePolicy, normalize_severity


@dataclass
class GateDecision:
    passed: bool
    blocking: list[dict] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def decision(self) -> str:
        """``blocked`` | ``error`` | ``passed`` (as stored on ``gate_runs``)."""
        if self.blocking:
            return "blocked"
        if self.errors:
            return "error"
        return "passed"

    def short_description(self) -> str:
        """e.g. ``2 critical, 5 high — merge blocked`` (fits a commit status)."""
        counts = ", ".join(f"{self.summary[s]} {s}" for s in SEVERITY_ORDER if self.summary.get(s))
        counts = counts or "no findings"
        if self.blocking:
            return f"{counts} — merge blocked"
        if self.errors:
            return f"{counts} — scan error, " + ("passed (fail-open)" if self.passed else "merge blocked")
        return f"{counts} — passed"


def evaluate(findings: list[dict], policy: GatePolicy, errors: list[str] | None = None) -> GateDecision:
    """Block on any finding at/above ``policy.fail_on``.

    ``errors`` are infra/scanner failures. With ``fail_open`` they produce a
    warning and the gate still passes; by default (fail-closed) they block.
    """
    errors = list(errors or [])
    threshold = SEVERITY_RANK[policy.fail_on]

    summary = {s: 0 for s in SEVERITY_ORDER}
    blocking: list[dict] = []
    for f in findings:
        sev = normalize_severity(f.get("severity"))
        summary[sev] += 1
        if SEVERITY_RANK[sev] >= threshold:
            blocking.append(f)

    reasons: list[str] = []
    passed = True
    if blocking:
        passed = False
        at_or_above = ", ".join(
            f"{summary[s]} {s}" for s in SEVERITY_ORDER if summary[s] and SEVERITY_RANK[s] >= threshold
        )
        reasons.append(f"{at_or_above} finding(s) at or above '{policy.fail_on}'")
    for err in errors:
        if policy.fail_open:
            reasons.append(f"warning: {err} (fail-open, ignored)")
        else:
            passed = False
            reasons.append(f"{err} (fail-closed)")
    if passed and not errors:
        reasons.append(f"no findings at or above '{policy.fail_on}'")

    return GateDecision(passed=passed, blocking=blocking, summary=summary, reasons=reasons, errors=errors)
