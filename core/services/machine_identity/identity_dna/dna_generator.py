"""Create a unique behavioural "DNA" strand for a machine identity.

The DNA is a set of stable traits (issuance context, scope shape, expected
call patterns) plus an evolving behavioural vector. Identity theft shows up as
a live signal that no longer matches the strand.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

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
