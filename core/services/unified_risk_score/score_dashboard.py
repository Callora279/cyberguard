"""Assemble the dashboard payload: current score, trend, breakdown, advice."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, RiskScore
from core.services.unified_risk_score import score_calculator, score_model


def _recommendations(breakdown: dict) -> list[dict]:
    tips = {
        "ai_governance": "Tighten AI usage policy and clear the human-review queue.",
        "security_debt": "Remediate critical findings and rotate any exposed secrets.",
        "supply_chain": "Upgrade dependencies with high/critical CVEs; regenerate the SBOM.",
        "machine_identity": "Rotate stale credentials and revoke expired identities.",
        "fraud_detection": "Investigate open fraud alerts and confirm/dismiss them.",
    }
    out = []
    for module, sc in sorted(breakdown.items(), key=lambda kv: kv[1]):
        if sc < 80:
            out.append({"module": module, "score": sc, "action": tips[module], "impact": round((80 - sc) * 0.2, 1)})
    return out[:4]


def build(org_id: str, *, recalculate: bool = True) -> dict:
    current = (
        score_calculator.calculate(org_id)
        if recalculate
        else _latest(org_id)
    )
    history = history_series(org_id, days=30)
    with session_scope() as db:
        open_alerts = db.scalars(
            select(Alert)
            .where(Alert.org_id == org_id, Alert.acknowledged.is_(False))
            .order_by(Alert.created_at.desc())
            .limit(10)
        ).all()
        alert_feed = [
            {"id": a.id, "module": a.module, "severity": a.severity, "title": a.title, "created_at": a.created_at}
            for a in open_alerts
        ]
    return {
        "org_id": org_id,
        "score": current["overall"],
        "grade": current["grade"],
        "breakdown": current["breakdown"],
        "trend_30d": history,
        "forecast": score_model.predict(org_id),
        "alert_feed": alert_feed,
        "recommendations": _recommendations(current["breakdown"]),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _latest(org_id: str) -> dict:
    with session_scope() as db:
        row = db.scalar(
            select(RiskScore).where(RiskScore.org_id == org_id).order_by(RiskScore.timestamp.desc())
        )
    if not row:
        return score_calculator.calculate(org_id)
    return {"overall": row.overall, "grade": row.grade, "breakdown": row.breakdown_json}


def history_series(org_id: str, *, days: int = 30) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as db:
        rows = db.scalars(
            select(RiskScore)
            .where(RiskScore.org_id == org_id, RiskScore.timestamp >= since)
            .order_by(RiskScore.timestamp)
        ).all()
    return [{"t": r.timestamp.isoformat(), "score": r.overall, "grade": r.grade} for r in rows]
