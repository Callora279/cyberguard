"""Analyse threat trends: emerging vectors, industry + geographic patterns.

Pulls a light signal from public feeds where available (CISA KEV) and blends
it with an internal moving picture of alert categories.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, RiskScore
from core.utils.logger import get_logger
from core.utils.notify import send_alert
from core.utils.timeutil import as_aware

logger = get_logger("predictive_risk.trend_analyzer")

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _kev_recent(days: int = 45) -> list[dict]:
    try:
        r = httpx.get(_KEV_URL, timeout=15.0)
        r.raise_for_status()
        cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)
        out = []
        for v in r.json().get("vulnerabilities", []):
            try:
                added = datetime.fromisoformat(v["dateAdded"]).date()
            except (KeyError, ValueError):
                continue
            if added >= cutoff:
                out.append({"cve": v.get("cveID"), "vendor": v.get("vendorProject"), "name": v.get("vulnerabilityName")})
        return out
    except httpx.HTTPError as exc:
        logger.info("KEV feed unavailable: %s", exc)
        return []


def current_threat_landscape() -> dict:
    kev = _kev_recent()
    vendors = Counter(v["vendor"] for v in kev if v.get("vendor"))
    ai_terms = sum(1 for v in kev if any(t in (v.get("name") or "").lower() for t in ("ai", "llm", "model", "prompt")))
    return {
        "source": "CISA KEV + internal",
        "recently_exploited_count": len(kev),
        "top_targeted_vendors": vendors.most_common(5),
        "ai_attack_momentum": round(min(1.0, ai_terms / 10.0), 2),
        "fraud_momentum": 0.3,  # placeholder industry signal
        "emerging_vectors": _emerging_vectors(kev),
    }


def _emerging_vectors(kev: list[dict]) -> list[str]:
    text = " ".join((v.get("name") or "").lower() for v in kev)
    vectors = []
    for kw, label in (
        ("remote code execution", "unauthenticated RCE in edge devices"),
        ("deserialization", "insecure deserialization"),
        ("authentication bypass", "authentication bypass"),
        ("supply chain", "supply-chain compromise"),
        ("prompt", "LLM prompt injection"),
    ):
        if kw in text:
            vectors.append(label)
    return vectors or ["credential phishing", "third-party breach spillover"]


def internal_trends(org_id: str, *, days: int = 60) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as db:
        rows = db.scalars(
            select(Alert).where(Alert.org_id == org_id, Alert.created_at >= since)
        ).all()
    by_module = Counter(a.module for a in rows)
    half = since + timedelta(days=days / 2)
    recent = Counter(a.module for a in rows if as_aware(a.created_at) >= half)
    older = Counter(a.module for a in rows if as_aware(a.created_at) < half)
    rising = [m for m in by_module if recent[m] > older[m] * 1.5 and recent[m] >= 2]
    return {
        "window_days": days,
        "alerts_by_module": dict(by_module),
        "rising_modules": rising,
        "total_alerts": len(rows),
    }


# ---------------------------------------------------------------------------
# Score-over-time tracking (Phase 3): trend direction + which modules are
# trending bad + alert when the overall score drops sharply.
# ---------------------------------------------------------------------------
def score_trend(org_id: str, *, days: int = 90) -> dict:
    """Track the risk score over time and classify the trend direction.

    Thin, UI-friendly wrapper around ``unified_risk_score.score_model`` (the
    OLS projection already lives there) plus the module-level "trending bad"
    signal from :func:`internal_trends`.
    """
    from core.services.unified_risk_score import score_model

    trend = score_model.trend_analysis(org_id)
    modules = internal_trends(org_id, days=min(days, 60))
    return {
        "org_id": org_id,
        "points": trend["points"],
        "direction": trend["prediction"].get("direction", "unknown"),
        "confidence": trend["prediction"].get("confidence", "low"),
        "trending_bad_modules": modules["rising_modules"],
        "anomaly": trend["anomaly"],
    }


def check_score_drop(org_id: str, *, threshold: float = 10.0) -> dict:
    """Compare the two most recent risk-score readings and raise an alert if
    the score dropped by more than ``threshold`` points."""
    with session_scope() as db:
        rows = db.scalars(
            select(RiskScore).where(RiskScore.org_id == org_id).order_by(RiskScore.timestamp.desc()).limit(2)
        ).all()

    if len(rows) < 2:
        return {"dropped": False, "reason": "insufficient history", "threshold": threshold}

    latest, previous = rows[0], rows[1]
    drop = round(previous.overall - latest.overall, 1)
    dropped = drop > threshold

    if dropped:
        send_alert(
            org_id,
            module="predictive_risk",
            severity="high",
            title=f"Risk score dropped {drop} points",
            body=f"Overall risk score fell from {previous.overall:.1f} to {latest.overall:.1f} "
            f"(alert threshold: {threshold} points).",
            context={"previous": previous.overall, "current": latest.overall, "drop": drop, "threshold": threshold},
        )
        logger.warning("risk score drop for org=%s: %.1f -> %.1f (-%.1f)", org_id, previous.overall, latest.overall, drop)

    return {
        "dropped": dropped,
        "current": latest.overall,
        "previous": previous.overall,
        "drop": drop,
        "threshold": threshold,
    }
