"""Lightweight predictive model + anomaly detection over historical risk scores.

Uses ordinary least squares on the recent series (no ML dependency) to project
the trend, and a z-score check on first differences to flag anomalies.
"""
from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean, pstdev

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import RiskScore


def _series(org_id: str, limit: int = 90) -> list[tuple[datetime, float]]:
    with session_scope() as db:
        rows = db.scalars(
            select(RiskScore)
            .where(RiskScore.org_id == org_id)
            .order_by(RiskScore.timestamp.desc())
            .limit(limit)
        ).all()
    return [(r.timestamp, r.overall) for r in reversed(rows)]


def _ols(y: list[float]) -> tuple[float, float]:
    n = len(y)
    if n < 2:
        return 0.0, (y[0] if y else 0.0)
    xs = list(range(n))
    mx, my = mean(xs), mean(y)
    denom = sum((x - mx) ** 2 for x in xs) or 1.0
    slope = sum((x - mx) * (v - my) for x, v in zip(xs, y)) / denom
    intercept = my - slope * mx
    return slope, intercept


def predict(org_id: str, *, horizon_days: int = 30) -> dict:
    series = _series(org_id)
    y = [v for _, v in series]
    if len(y) < 3:
        return {"prediction": y[-1] if y else None, "confidence": "low", "reason": "insufficient history"}
    slope, intercept = _ols(y)
    projected = intercept + slope * (len(y) - 1 + horizon_days)
    projected = max(0.0, min(100.0, projected))
    residuals = [v - (intercept + slope * i) for i, v in enumerate(y)]
    rmse = (mean(r ** 2 for r in residuals)) ** 0.5
    return {
        "current": round(y[-1], 2),
        "predicted": round(projected, 2),
        "horizon_days": horizon_days,
        "daily_trend": round(slope, 4),
        "direction": "improving" if slope > 0.05 else ("declining" if slope < -0.05 else "stable"),
        "confidence": "high" if rmse < 3 else ("medium" if rmse < 8 else "low"),
        "rmse": round(rmse, 2),
    }


def detect_anomaly(org_id: str) -> dict:
    y = [v for _, v in _series(org_id)]
    if len(y) < 8:
        return {"anomaly": False, "reason": "insufficient history"}
    diffs = [y[i] - y[i - 1] for i in range(1, len(y))]
    mu, sd = mean(diffs), pstdev(diffs) or 1.0
    last = diffs[-1]
    z = (last - mu) / sd
    return {
        "anomaly": abs(z) > 3,
        "z_score": round(z, 2),
        "last_change": round(last, 2),
        "note": "sudden posture drop" if z < -3 else ("sudden posture jump" if z > 3 else "within normal variation"),
    }


def trend_analysis(org_id: str) -> dict:
    series = _series(org_id)
    return {
        "points": [{"t": t.isoformat(), "score": v} for t, v in series],
        "prediction": predict(org_id),
        "anomaly": detect_anomaly(org_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
