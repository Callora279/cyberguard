"""Detect identity theft / compromise by comparing live signals to stored DNA."""
from __future__ import annotations

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
