"""Correlate fraud patterns across time and entities (rings, bursts, reuse)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import FraudAlert
from core.utils.timeutil import as_aware

# Safe default returned when there is nothing to correlate (missing/empty case).
_SAFE_DEFAULT = {
    "boost": 0.0,
    "signals": [],
    "related_alert_count": 0,
    "ring_suspected": False,
}


def _as_dict(value: object) -> dict:
    """Coerce ``None`` / non-dict values to an empty dict so ``.get()`` is safe."""
    return value if isinstance(value, dict) else {}


def correlate(org_id: str, case: dict | None, base_assessment: dict | None = None) -> dict:
    """Look for links between this case and recent fraud alerts.

    Every field of ``case`` is optional and may be ``None``; this function never
    raises on missing or null input — it returns :data:`_SAFE_DEFAULT` instead.
    """
    case = _as_dict(case)
    base_assessment = _as_dict(base_assessment)
    if not case or not org_id:
        return dict(_SAFE_DEFAULT)

    since = datetime.now(timezone.utc) - timedelta(days=30)
    signals: list[str] = []
    boost = 0.0

    identity = _as_dict(case.get("identity"))
    context = _as_dict(case.get("context"))
    invoice = _as_dict(case.get("invoice"))

    subject = str(case.get("subject") or identity.get("email") or "").lower()
    ip = context.get("ip")
    iban = invoice.get("iban")

    with session_scope() as db:
        recent = db.scalars(
            select(FraudAlert).where(
                FraudAlert.org_id == org_id, FraudAlert.created_at >= since
            )
        ).all()

    same_subject = [a for a in recent if subject and subject in str(a.subject).lower()]
    if len(same_subject) >= 2:
        boost += 12
        signals.append(f"{len(same_subject)} prior alerts for the same subject in 30d")

    # burst: many alerts in a short window suggests a coordinated attack
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = [a for a in recent if as_aware(a.created_at) >= cutoff_24h]
    if len(last_24h) >= 5:
        boost += 10
        signals.append(f"fraud burst: {len(last_24h)} alerts in the last 24h")

    # shared infrastructure (IP / IBAN reuse across alerts)
    if ip:
        ip_matches = [a for a in recent if ip in str(a.signals)]
        if ip_matches:
            boost += 8
            signals.append(f"source IP reused across {len(ip_matches)} alerts (possible ring)")
    if iban:
        iban_matches = [a for a in recent if iban in str(a.signals)]
        if iban_matches:
            boost += 15
            signals.append(f"beneficiary IBAN seen in {len(iban_matches)} other alerts")

    return {
        "boost": round(min(boost, 30.0), 1),
        "signals": signals,
        "related_alert_count": len(same_subject),
        "ring_suspected": bool(iban and signals),
    }


def pattern_timeline(org_id: str, *, days: int = 30) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as db:
        rows = db.scalars(
            select(FraudAlert).where(
                FraudAlert.org_id == org_id, FraudAlert.created_at >= since
            ).order_by(FraudAlert.created_at)
        ).all()
    buckets: dict[str, dict] = {}
    for r in rows:
        day = r.created_at.date().isoformat()
        b = buckets.setdefault(day, {"count": 0, "avg_score": 0.0, "types": {}})
        b["count"] += 1
        b["avg_score"] += r.risk_score
        b["types"][r.type] = b["types"].get(r.type, 0) + 1
    for b in buckets.values():
        b["avg_score"] = round(b["avg_score"] / max(b["count"], 1), 1)
    return {"days": days, "daily": buckets, "total": len(rows)}
