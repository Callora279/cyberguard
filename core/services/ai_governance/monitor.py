"""AI usage monitor.

Registers as an observer on ``core.utils.ai_client`` so every AI call made
anywhere in CyberGuard is:
    * persisted as an ``ai_interactions`` row
    * risk-scored
    * checked for anomalous behaviour vs the rolling baseline
    * rolled up for token / cost tracking
    * turned into an ``alerts`` row on policy violation or anomaly
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from statistics import mean, pstdev

from sqlalchemy import func, select

from core.database.db import session_scope
from core.database.models import AIInteraction, Alert
from core.services.ai_governance.risk_scoring import score_interaction
from core.utils.ai_client import AICallRecord, register_observer
from core.utils.logger import get_logger

logger = get_logger("ai_governance.monitor")

# rolling window of recent (tokens, latency, risk) for cheap anomaly detection
_WINDOW: deque[tuple[int, float, float]] = deque(maxlen=200)
_RISK_ALERT_THRESHOLD = 60.0


def _preview(text: str, limit: int = 500) -> str:
    return text[:limit]


def _detect_anomaly(record: AICallRecord, risk: float) -> list[str]:
    reasons: list[str] = []
    if len(_WINDOW) >= 20:
        tok = [w[0] for w in _WINDOW]
        lat = [w[1] for w in _WINDOW]
        tok_mu, tok_sd = mean(tok), pstdev(tok) or 1.0
        lat_mu, lat_sd = mean(lat), pstdev(lat) or 1.0
        if record.total_tokens > tok_mu + 3 * tok_sd:
            reasons.append(
                f"token spike: {record.total_tokens} vs baseline ~{tok_mu:.0f}"
            )
        if record.latency_ms > lat_mu + 4 * lat_sd:
            reasons.append(
                f"latency spike: {record.latency_ms:.0f}ms vs baseline ~{lat_mu:.0f}ms"
            )
    if risk >= _RISK_ALERT_THRESHOLD:
        reasons.append(f"high interaction risk score: {risk}")
    _WINDOW.append((record.total_tokens, record.latency_ms, risk))
    return reasons


def record_interaction(record: AICallRecord) -> str:
    """Observer entrypoint. Returns the created interaction id."""
    org_id = str(record.metadata.get("org_id", "unknown"))
    breakdown = score_interaction(record.prompt, record.response)
    risk = breakdown.score
    decision = str(record.metadata.get("policy_decision", "allow"))
    anomalies = _detect_anomaly(record, risk)

    with session_scope() as db:
        interaction = AIInteraction(
            org_id=org_id,
            model=record.model,
            prompt_hash=record.prompt_hash,
            prompt_preview=_preview(record.prompt),
            response_preview=_preview(record.response),
            prompt_tokens=record.prompt_tokens,
            completion_tokens=record.completion_tokens,
            total_tokens=record.total_tokens,
            cost_usd=record.cost_usd,
            latency_ms=record.latency_ms,
            risk_score=risk,
            risk_breakdown=breakdown.as_dict(),
            policy_decision=decision,
        )
        db.add(interaction)
        db.flush()
        iid = interaction.id

        if anomalies or decision == "block":
            sev = "critical" if decision == "block" else ("high" if risk >= 75 else "medium")
            db.add(
                Alert(
                    org_id=org_id,
                    module="ai_governance",
                    severity=sev,
                    title="AI behaviour anomaly" if anomalies else "AI policy violation",
                    body="; ".join(anomalies) or "request blocked by policy",
                    context={
                        "interaction_id": iid,
                        "model": record.model,
                        "risk": breakdown.as_dict(),
                        "prompt_hash": record.prompt_hash,
                    },
                )
            )
    logger.info("recorded ai interaction %s risk=%.1f decision=%s", iid, risk, decision)
    return iid


def usage_summary(org_id: str, days: int = 30) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as db:
        q = select(
            func.count(AIInteraction.id),
            func.coalesce(func.sum(AIInteraction.total_tokens), 0),
            func.coalesce(func.sum(AIInteraction.cost_usd), 0.0),
            func.coalesce(func.avg(AIInteraction.risk_score), 0.0),
        ).where(AIInteraction.org_id == org_id, AIInteraction.timestamp >= since)
        calls, tokens, cost, avg_risk = db.execute(q).one()
        blocked = db.scalar(
            select(func.count(AIInteraction.id)).where(
                AIInteraction.org_id == org_id,
                AIInteraction.timestamp >= since,
                AIInteraction.policy_decision == "block",
            )
        )
        by_model = db.execute(
            select(AIInteraction.model, func.count(AIInteraction.id))
            .where(AIInteraction.org_id == org_id, AIInteraction.timestamp >= since)
            .group_by(AIInteraction.model)
        ).all()
    return {
        "window_days": days,
        "calls": int(calls),
        "total_tokens": int(tokens),
        "estimated_cost_usd": round(float(cost), 4),
        "avg_risk_score": round(float(avg_risk), 2),
        "blocked_calls": int(blocked or 0),
        "by_model": {m: c for m, c in by_model},
    }


def install() -> None:
    register_observer(record_interaction)
    logger.info("ai_governance monitor installed as ai_client observer")
