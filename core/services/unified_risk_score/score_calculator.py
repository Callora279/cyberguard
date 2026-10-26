"""Combine every module score into one 0-100 posture score with a letter grade."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import RiskScore
from core.services.ai_fraud_detection import fraud_risk_scoring
from core.services.ai_governance import monitor as ai_monitor
from core.services.iac_scan import reporting as iac_reporting
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
    # Only counted once the org has an IaC scan; weights are renormalised over
    # the pillars present, so orgs without one score exactly as before.
    "iac": 0.20,
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


_GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]
# Headline grade can't be better than this while a module is failing or an
# open critical finding exists.
GRADE_CAP = "C"
MODULE_FLOOR = 40.0


def weakest_module(breakdown: dict) -> dict | None:
    if not breakdown:
        return None
    name, score = min(breakdown.items(), key=lambda kv: kv[1])
    return {"name": name, "score": score}


def _cap_grade(grade: str, breakdown: dict, open_critical: int) -> tuple[str, str | None]:
    reason = None
    if any(v < MODULE_FLOOR for v in breakdown.values()):
        reason = f"a module scores below {MODULE_FLOOR:g}"
    elif open_critical > 0:
        reason = f"{open_critical} open critical finding{'s' if open_critical != 1 else ''}"
    if reason and _GRADE_ORDER.index(grade) < _GRADE_ORDER.index(GRADE_CAP):
        return GRADE_CAP, reason
    return grade, None


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


def _signals(org_id: str) -> dict:
    """The raw, human-readable inputs behind each module sub-score."""
    usage = ai_monitor.usage_summary(org_id, days=30)
    debt = debt_reporting.summary(org_id)
    components = sc_alerts.list_components(org_id)
    reg = identity_registry.list_registry(org_id)
    fraud_open = fraud_risk_scoring.list_alerts(org_id, status="open")
    iac = iac_reporting.summary(org_id)

    signals = {
        "ai_governance": {
            "calls_30d": usage["calls"],
            "blocked_calls": usage["blocked_calls"],
            "blocked_pct": round(
                (usage["blocked_calls"] / usage["calls"] * 100) if usage["calls"] else 0.0, 1
            ),
            "avg_interaction_risk": usage["avg_risk_score"],
        },
        "security_debt": {
            "critical": debt["by_severity"].get("critical", 0),
            "high": debt["by_severity"].get("high", 0),
            "total_findings": debt["total_findings"],
        },
        "supply_chain": {
            "components": len(components),
            "critical_cves": sum(1 for c in components if c["max_cvss"] >= 9.0),
            "vulnerable_components": sum(1 for c in components if c["cve_count"] > 0),
        },
        "machine_identity": {
            "total": len(reg),
            "expired_or_revoked": sum(1 for r in reg if r["status"] in ("expired", "revoked")),
            "expired_pct": round(
                (sum(1 for r in reg if r["status"] in ("expired", "revoked")) / len(reg) * 100)
                if reg else 0.0, 1
            ),
        },
        "fraud_detection": {
            "open_alerts": len(fraud_open),
            "high_risk_alerts": sum(1 for a in fraud_open if a["risk_score"] >= 70),
        },
    }
    if iac:
        signals["iac"] = {
            "scans": iac["scans"],
            "critical": iac["by_severity"].get("critical", 0),
            "high": iac["by_severity"].get("high", 0),
            "total_findings": iac["total_findings"],
        }
    return signals


def calculate(org_id: str, *, persist: bool = True) -> dict:
    debt = debt_reporting.summary(org_id)
    breakdown = {
        "ai_governance": _ai_governance_score(org_id),
        "security_debt": debt["module_score"],
        "supply_chain": sc_alerts.module_score(sc_alerts.list_components(org_id)),
        "machine_identity": _machine_identity_score(org_id),
        "fraud_detection": fraud_risk_scoring.module_score(org_id),
    }
    iac = iac_reporting.summary(org_id)
    if iac:
        breakdown["iac"] = iac["module_score"]
    weights = {k: w for k, w in WEIGHTS.items() if k in breakdown}
    total_weight = sum(weights.values())
    weights = {k: round(w / total_weight, 4) for k, w in weights.items()}
    overall = round(sum(breakdown[k] * w for k, w in weights.items()), 2)
    grade, grade_capped_by = _cap_grade(
        _grade(overall), breakdown, debt["by_severity"].get("critical", 0)
    )

    result = {
        "org_id": org_id,
        "overall": overall,
        "grade": grade,
        "grade_capped_by": grade_capped_by,
        "weakest_module": weakest_module(breakdown),
        "breakdown": breakdown,
        "signals": _signals(org_id),
        "weights": weights,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if persist:
        # At most one snapshot per UTC day: upsert the latest score into today's row.
        now = datetime.now(timezone.utc)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        with session_scope() as db:
            today = db.scalar(
                select(RiskScore)
                .where(RiskScore.org_id == org_id, RiskScore.timestamp >= day_start)
                .order_by(RiskScore.timestamp.desc())
            )
            if today is None:
                db.add(
                    RiskScore(
                        org_id=org_id,
                        overall=overall,
                        grade=grade,
                        breakdown_json=breakdown,
                        timestamp=now,
                    )
                )
            else:
                today.overall = overall
                today.grade = grade
                today.breakdown_json = breakdown
                today.timestamp = now
    logger.info("unified risk for %s: %.1f (%s)", org_id, overall, grade)
    return result
