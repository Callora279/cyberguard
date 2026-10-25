"""Detect identity theft / compromise by comparing live signals to stored DNA."""
from __future__ import annotations

from statistics import mean, pstdev

from core.services.machine_identity.behaviour_monitor import _load as _load_behaviour
from core.services.machine_identity.identity_dna import dna_generator, dna_store
from core.utils.logger import get_logger

logger = get_logger("machine_identity.dna_analyzer")


def _vector_distance(a: dict, b: dict) -> float:
    keys = set(a) | set(b)
    return sum((a.get(k, 0.0) - b.get(k, 0.0)) ** 2 for k in keys) ** 0.5


def analyze(identity_id: str, *, live_signal: dict | None = None) -> dict:
    dna = dna_store.load(identity_id)
    if not dna:
        return {"identity_id": identity_id, "compromise_score": 0.0, "reasons": ["no DNA on file"], "baseline_ready": False}

    # rebuild an "observed" vector from the behaviour profile
    prof = _load_behaviour(identity_id)
    events = prof.get("events", 0)
    observed = {
        "distinct_ips": float(len(prof.get("ips", {}))),
        "distinct_geos": float(len(prof.get("geos", {}))),
        "write_ratio": (
            sum(c for a, c in prof.get("actions", {}).items() if a in ("write", "admin"))
            / max(events, 1)
        ),
        "night_ratio": sum(c for h, c in prof.get("hours", {}).items() if 0 <= int(h) < 6) / max(events, 1),
        "burstiness": min(1.0, events / 50.0),
    }

    reasons: list[str] = []
    baseline_ready = dna.get("samples", 0) >= 20 or events >= 20

    dist = _vector_distance(observed, dna["behaviour_vector"])
    if baseline_ready and dist > 2.5:
        reasons.append(f"behavioural DNA drift (distance {dist:.2f})")

    if live_signal:
        if live_signal.get("geo") and str(live_signal["geo"]) not in prof.get("geos", {}) and baseline_ready:
            reasons.append(f"live access from never-seen geo {live_signal['geo']}")
        if (
            live_signal.get("action") in ("write", "admin")
            and dna["traits"].get("automation_class") == "read-only-automation"
        ):
            reasons.append("privileged action from a read-only identity DNA")

    compromise = min(100.0, len(reasons) * 35.0 + max(0.0, (dist - 1.0) * 12.0))
    result = {
        "identity_id": identity_id,
        "compromise_score": round(compromise, 1),
        "verdict": "compromised" if compromise >= 70 else ("suspicious" if compromise >= 35 else "healthy"),
        "reasons": reasons,
        "dna_distance": round(dist, 3),
        "baseline_ready": baseline_ready,
    }
    if compromise >= 35:
        logger.warning("identity DNA analysis for %s: %s", identity_id, result["verdict"])
    return result


def refresh(identity_id: str, events: list[dict]) -> dict:
    dna = dna_store.load(identity_id)
    if not dna:
        return {}
    dna = dna_generator.evolve(dna, events)
    dna_store.save(identity_id, dna)
    return dna


# ---------------------------------------------------------------------------
# Fingerprint comparison (Phase 3): compare a live access event against the
# {normal_hours, normal_endpoints, avg_requests_per_hour, normal_ips}
# behavioural fingerprint and alert on deviation.
# ---------------------------------------------------------------------------
def _hour_is_anomalous(hour: int, histogram: dict) -> bool:
    """>2 std dev below the identity's typical hourly frequency = unusual hour."""
    counts = [histogram.get(str(h), 0) for h in range(24)]
    if sum(counts) < 24:  # not enough history for a meaningful distribution
        return False
    mu, sd = mean(counts), pstdev(counts)
    if sd == 0:
        return counts[hour] == 0
    return counts[hour] < mu - 2 * sd


def analyze_fingerprint(identity_id: str, *, live_event: dict | None = None) -> dict:
    """Compare ``live_event`` (``{hour, endpoint, ip, requests_last_hour}``)
    against the identity's stored behavioural fingerprint.

    Alerts on: access outside normal hours (>2 std dev), a never-seen
    endpoint, request rate >3x the historical average, or a new IP range.
    Severity scales with how many/how far the signals deviate.
    """
    fp = dna_store.load_fingerprint(identity_id)
    if not fp or fp.get("sample_count", 0) == 0:
        return {
            "identity_id": identity_id, "deviation_score": 0.0, "reasons": [],
            "severity": "info", "fingerprint_ready": False,
        }

    reasons: list[str] = []
    deviation = 0.0
    live_event = live_event or {}

    hour = live_event.get("hour")
    if hour is not None and int(hour) not in fp["normal_hours"] and _hour_is_anomalous(int(hour), fp.get("hour_histogram", {})):
        reasons.append(f"access outside normal hours ({int(hour):02d}:00, >2σ below baseline)")
        deviation += 30.0

    endpoint = live_event.get("endpoint")
    if endpoint and endpoint not in fp["normal_endpoints"]:
        reasons.append(f"new endpoint accessed: {endpoint}")
        deviation += 25.0

    rate = live_event.get("requests_last_hour")
    baseline_rate = fp.get("avg_requests_per_hour", 0.0)
    if rate is not None and baseline_rate > 0 and rate > baseline_rate * 3:
        reasons.append(f"request rate {rate}/hr is {rate / baseline_rate:.1f}x the {baseline_rate}/hr baseline")
        deviation += 30.0 * min(2.0, rate / (baseline_rate * 3))

    ip = live_event.get("ip")
    if ip:
        prefix = dna_generator.ip_prefix(ip)
        if prefix not in fp["normal_ips"]:
            reasons.append(f"access from new IP range {prefix}")
            deviation += 25.0

    deviation = round(min(100.0, deviation), 1)
    severity = "critical" if deviation >= 80 else "high" if deviation >= 50 else "medium" if deviation >= 25 else "low"

    result = {
        "identity_id": identity_id,
        "deviation_score": deviation,
        "reasons": reasons,
        "severity": severity if reasons else "info",
        "fingerprint_ready": True,
        "fingerprint_sample_count": fp["sample_count"],
    }
    if reasons:
        logger.warning("identity fingerprint deviation for %s: %s (%s)", identity_id, severity, "; ".join(reasons))
    return result
