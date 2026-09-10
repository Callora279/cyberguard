"""Detect anomalies in a live AI interaction vs the stored baseline fingerprint."""
from __future__ import annotations

from datetime import datetime, timezone

from core.services.ai_governance.ai_behavior_fingerprinting import fingerprint_store
from core.utils.ai_client import AICallRecord
from core.utils.logger import get_logger

logger = get_logger("ai_governance.fingerprint_analyzer")

_Z = 3.0  # standard deviations before a metric is flagged


def _z_exceeds(value: float, stats: dict, factor: float = _Z) -> bool:
    std = stats.get("std") or 0.0
    if std <= 0:
        return value > (stats.get("max", 0.0) * 1.5 + 1)
    return abs(value - stats.get("mean", 0.0)) > factor * std


def check(org_id: str, record: AICallRecord) -> dict:
    fp = fingerprint_store.get_or_build(org_id)
    if fp.get("sample_size", 0) < 15:
        return {"anomalous": False, "reasons": [], "baseline_ready": False}

    reasons: list[str] = []
    if _z_exceeds(record.total_tokens, fp["tokens"]):
        reasons.append(f"token count {record.total_tokens} deviates from baseline")
    if _z_exceeds(record.latency_ms, fp["latency_ms"], factor=4.0):
        reasons.append(f"latency {record.latency_ms:.0f}ms deviates from baseline")
    if _z_exceeds(record.cost_usd, fp["cost_usd"]):
        reasons.append(f"cost ${record.cost_usd} deviates from baseline")

    if record.model not in fp.get("model_mix", {}):
        reasons.append(f"model '{record.model}' never seen in baseline")

    hour = datetime.now(timezone.utc).hour
    active = set(fp.get("active_hours", []))
    if active and hour not in active:
        reasons.append(f"off-hours activity at {hour:02d}:00 UTC")

    result = {
        "anomalous": bool(reasons),
        "reasons": reasons,
        "baseline_ready": True,
        "baseline_generated_at": fp.get("generated_at"),
    }
    if reasons:
        logger.warning("fingerprint anomaly org=%s: %s", org_id, reasons)
    return result


def drift_report(org_id: str) -> dict:
    """Compare the two most recent fingerprints to surface behavioural drift."""
    hist = fingerprint_store.history(org_id, limit=2)
    if len(hist) < 2:
        return {"drift": False, "reason": "not enough fingerprint history"}
    new, old = hist[0], hist[1]
    changes = {}
    for metric in ("tokens", "latency_ms", "cost_usd", "risk_score"):
        o = old.get(metric, {}).get("mean", 0.0)
        n = new.get(metric, {}).get("mean", 0.0)
        if o and abs(n - o) / o > 0.4:
            changes[metric] = {"from": o, "to": n}
    return {"drift": bool(changes), "changes": changes}
