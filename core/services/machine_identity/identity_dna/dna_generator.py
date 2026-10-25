"""Create a unique behavioural "DNA" strand for a machine identity.

The DNA is a set of stable traits (issuance context, scope shape, expected
call patterns) plus an evolving behavioural vector. Identity theft shows up as
a live signal that no longer matches the strand.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timedelta, timezone

from core.services.machine_identity.identity_dna import dna_store

_TRAIT_ORDER = ["type", "scope_breadth", "privileged", "automation_class", "issuance_epoch"]


def _automation_class(scopes: list[str]) -> str:
    joined = " ".join(scopes).lower()
    if any(k in joined for k in ("deploy", "release", "infra", "admin")):
        return "privileged-automation"
    if any(k in joined for k in ("read", "list", "get")):
        return "read-only-automation"
    return "general-automation"


def generate_seed(identity_id: str, identity_type: str, scopes: list[str]) -> dict:
    now = datetime.now(timezone.utc)
    traits = {
        "type": identity_type,
        "scope_breadth": len(scopes),
        "privileged": any(s in ("write", "admin") or "admin" in s for s in scopes),
        "automation_class": _automation_class(scopes),
        "issuance_epoch": int(now.timestamp()),
    }
    strand = hashlib.sha256(
        "|".join(f"{k}={traits[k]}" for k in _TRAIT_ORDER).encode()
    ).hexdigest()
    return {
        "identity_id": identity_id,
        "strand": strand,
        "traits": traits,
        "behaviour_vector": {
            "distinct_ips": 0.0,
            "distinct_geos": 0.0,
            "write_ratio": 0.0,
            "night_ratio": 0.0,
            "burstiness": 0.0,
        },
        "created_at": now.isoformat(),
        "samples": 0,
    }


def evolve(dna: dict, events: list[dict]) -> dict:
    """Fold recent access events into the behavioural vector (EWMA)."""
    if not events:
        return dna
    alpha = 0.2
    ips = {e.get("ip") for e in events if e.get("ip")}
    geos = {e.get("geo") for e in events if e.get("geo")}
    writes = sum(1 for e in events if e.get("action") in ("write", "admin"))
    nights = sum(1 for e in events if 0 <= int(e.get("hour", 12)) < 6)
    n = len(events)

    observed = {
        "distinct_ips": float(len(ips)),
        "distinct_geos": float(len(geos)),
        "write_ratio": writes / n,
        "night_ratio": nights / n,
        "burstiness": min(1.0, n / 50.0),
    }
    vec = dna["behaviour_vector"]
    for k, v in observed.items():
        vec[k] = round((1 - alpha) * vec.get(k, 0.0) + alpha * v, 4)
    dna["samples"] = dna.get("samples", 0) + n
    dna["updated_at"] = datetime.now(timezone.utc).isoformat()
    return dna


# ---------------------------------------------------------------------------
# Behavioural fingerprint (Phase 3): track raw access events over a rolling
# window (default 7 days) and distil them into the exact shape requested —
# normal hours, normal endpoints, average hourly rate and normal IP ranges.
# ---------------------------------------------------------------------------
def ip_prefix(ip: str) -> str:
    """Mask the last octet so the fingerprint tracks IP *ranges*, not single
    addresses (a DHCP lease change shouldn't look like a new identity)."""
    parts = ip.split(".")
    return f"{'.'.join(parts[:3])}.x" if len(parts) == 4 else ip


def record_event(identity_id: str, *, endpoint: str, ip: str = "", ts: datetime | None = None) -> None:
    """Log one access event for later fingerprinting. Call this from wherever
    a machine identity's request is authenticated/handled."""
    ts = ts or datetime.now(timezone.utc)
    dna_store.append_event(
        identity_id,
        {"ts": ts.timestamp(), "hour": ts.hour, "endpoint": endpoint, "ip_prefix": ip_prefix(ip) if ip else ""},
    )


def generate_fingerprint(identity_id: str, *, days: int = 7, min_hour_share: float = 0.03) -> dict:
    """Build the behavioural fingerprint from the last ``days`` of events:

        {"normal_hours": [...], "normal_endpoints": [...],
         "avg_requests_per_hour": float, "normal_ips": [...]}
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
    events = [e for e in dna_store.load_events(identity_id) if e.get("ts", 0) >= cutoff]

    if not events:
        fingerprint = {
            "identity_id": identity_id, "window_days": days, "sample_count": 0,
            "normal_hours": [], "normal_endpoints": [], "avg_requests_per_hour": 0.0, "normal_ips": [],
            "hour_histogram": {}, "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        dna_store.save_fingerprint(identity_id, fingerprint)
        return fingerprint

    hour_counts = Counter(int(e["hour"]) for e in events)
    endpoint_counts = Counter(e["endpoint"] for e in events if e.get("endpoint"))
    ip_counts = Counter(e["ip_prefix"] for e in events if e.get("ip_prefix"))

    total = len(events)
    normal_hours = sorted(h for h, c in hour_counts.items() if c / total >= min_hour_share)
    normal_endpoints = sorted(endpoint_counts)
    normal_ips = sorted(ip_counts)

    span_hours = max(1.0, (max(e["ts"] for e in events) - min(e["ts"] for e in events)) / 3600.0)
    avg_requests_per_hour = round(total / span_hours, 1)

    fingerprint = {
        "identity_id": identity_id,
        "window_days": days,
        "sample_count": total,
        "normal_hours": normal_hours,
        "normal_endpoints": normal_endpoints,
        "avg_requests_per_hour": avg_requests_per_hour,
        "normal_ips": normal_ips,
        # kept for the >2-std-dev off-hours check in dna_analyzer
        "hour_histogram": {str(h): hour_counts.get(h, 0) for h in range(24)},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    dna_store.save_fingerprint(identity_id, fingerprint)
    return fingerprint
