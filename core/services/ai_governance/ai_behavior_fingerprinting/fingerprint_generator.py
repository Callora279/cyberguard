"""Build a behavioural fingerprint of *normal* AI usage for an organisation.

A fingerprint is a compact statistical profile derived from recent
``ai_interactions``: typical token sizes, latency, cost, risk, model mix,
prompt-length distribution and hour-of-day activity.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from statistics import mean, pstdev

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import AIInteraction


def _safe_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "p95": 0.0, "max": 0.0}
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    return {
        "mean": round(mean(values), 3),
        "std": round(pstdev(values) if len(values) > 1 else 0.0, 3),
        "p95": round(p95, 3),
        "max": round(max(values), 3),
    }


def generate(org_id: str, *, lookback_days: int = 30) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    with session_scope() as db:
        rows = db.scalars(
            select(AIInteraction).where(
                AIInteraction.org_id == org_id, AIInteraction.timestamp >= since
            )
        ).all()

    tokens = [r.total_tokens for r in rows]
    latency = [r.latency_ms for r in rows]
    cost = [r.cost_usd for r in rows]
    risk = [r.risk_score for r in rows]
    prompt_len = [len(r.prompt_preview) for r in rows]
    models = Counter(r.model for r in rows)
    hours = Counter(r.timestamp.astimezone(timezone.utc).hour for r in rows if r.timestamp)

    return {
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_size": len(rows),
        "lookback_days": lookback_days,
        "tokens": _safe_stats(tokens),
        "latency_ms": _safe_stats(latency),
        "cost_usd": _safe_stats(cost),
        "risk_score": _safe_stats(risk),
        "prompt_length": _safe_stats(prompt_len),
        "model_mix": {m: c / max(len(rows), 1) for m, c in models.items()},
        "active_hours": sorted(h for h, _ in hours.most_common(8)),
        "calls_per_day": round(len(rows) / max(lookback_days, 1), 2),
    }
