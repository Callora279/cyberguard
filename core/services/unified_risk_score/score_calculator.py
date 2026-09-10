"""Combine every module score into one 0-100 posture score with a letter grade."""
from __future__ import annotations

from datetime import datetime, timezone

from core.database.db import session_scope
from core.database.models import RiskScore
from core.services.ai_fraud_detection import fraud_risk_scoring
from core.services.ai_governance import monitor as ai_monitor
from core.services.machine_identity import identity_registry
from core.services.security_debt import reporting as debt_reporting
from core.services.supply_chain import alerts as sc_alerts
from core.utils.logger import get_logger

logger = get_logger("unified_risk.calculator")

WEIGHTS = {
    "ai_governance": 0.20,
    "security_debt": 0.20,
    "supply_chain": 0.20,
    "machine_identity": 0.20,
    "fraud_detection": 0.20,
}


def _grade(score: float) -> str:
    if score >= 95:
        return "A+"
    if score >= 88:
        return "A"
    if score >= 78:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _ai_governance_score(org_id: str) -> float:
    usage = ai_monitor.usage_summary(org_id, days=30)
    if usage["calls"] == 0:
        return 90.0
    penalty = usage["avg_risk_score"] * 0.6 + (usage["blocked_calls"] / usage["calls"]) * 40
    return round(max(0.0, 100.0 - penalty), 2)


def _machine_identity_score(org_id: str) -> float:
    reg = identity_registry.list_registry(org_id)
    if not reg:
        return 85.0
    bad = sum(1 for r in reg if r["status"] in ("expired", "revoked"))
    expiring = sum(1 for r in reg if r["status"] == "expiring")
    penalty = (bad / len(reg)) * 50 + (expiring / len(reg)) * 20
    return round(max(0.0, 100.0 - penalty), 2)


def calculate(org_id: str, *, persist: bool = True) -> dict:
    breakdown = {
        "ai_governance": _ai_governance_score(org_id),
        "security_debt": debt_reporting.summary(org_id)["module_score"],
        "supply_chain": sc_alerts.module_score(sc_alerts.list_components(org_id)),
        "machine_identity": _machine_identity_score(org_id),
        "fraud_detection": fraud_risk_scoring.module_score(org_id),
    }
    overall = round(sum(breakdown[k] * w for k, w in WEIGHTS.items()), 2)
    grade = _grade(overall)

    result = {
        "org_id": org_id,
        "overall": overall,
        "grade": grade,
        "breakdown": breakdown,
        "weights": WEIGHTS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if persist:
        with session_scope() as db:
            db.add(
                RiskScore(
                    org_id=org_id,
                    overall=overall,
                    grade=grade,
                    breakdown_json=breakdown,
                )
            )
    logger.info("unified risk for %s: %.1f (%s)", org_id, overall, grade)
    return result
