"""Baseline per-identity behaviour and alert on anomalies."""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from core.database.db import session_scope
from core.database.models import Alert
from core.utils.logger import get_logger

logger = get_logger("machine_identity.behaviour")

_DIR = Path(os.getenv("CYBERGUARD_STATE_DIR", ".cyberguard")) / "identity_behaviour"

# an access event: {identity_id, ip, geo, hour, resource, action, privileged}


def _bpath(identity_id: str) -> Path:
    _DIR.mkdir(parents=True, exist_ok=True)
    return _DIR / f"{identity_id}.json"


def _load(identity_id: str) -> dict:
    p = _bpath(identity_id)
    if p.exists():
        return json.loads(p.read_text())
    return {"ips": {}, "geos": {}, "hours": {}, "resources": {}, "actions": {}, "events": 0}


def _save(identity_id: str, profile: dict) -> None:
    _bpath(identity_id).write_text(json.dumps(profile, default=str))


def observe(event: dict) -> dict:
    """Record an access event and return an anomaly assessment."""
    identity_id = event["identity_id"]
    profile = _load(identity_id)
    reasons: list[str] = []
    baseline_ready = profile["events"] >= 30

    def seen(bucket: str, value) -> bool:
        return str(value) in profile.get(bucket, {})

    if baseline_ready:
        if event.get("ip") and not seen("ips", event["ip"]):
            reasons.append(f"new source IP {event['ip']}")
        if event.get("geo") and not seen("geos", event["geo"]):
            reasons.append(f"new geography {event['geo']}")
        hour = event.get("hour", datetime.now(timezone.utc).hour)
        common_hours = {int(h) for h, c in profile["hours"].items() if c >= profile["events"] * 0.02}
        if common_hours and hour not in common_hours:
            reasons.append(f"off-hours activity at {hour:02d}:00")
        if event.get("privileged") and not any(
            "admin" in r or "write" in r for r in profile["actions"]
        ):
            reasons.append("privilege escalation: first privileged action")
        if event.get("resource") and not seen("resources", event["resource"]):
            reasons.append(f"access to previously-unseen resource {event['resource']}")

    # update profile
    for bucket, key in (
        ("ips", event.get("ip")),
        ("geos", event.get("geo")),
        ("hours", event.get("hour", datetime.now(timezone.utc).hour)),
        ("resources", event.get("resource")),
        ("actions", event.get("action")),
    ):
        if key is None:
            continue
        profile[bucket][str(key)] = profile[bucket].get(str(key), 0) + 1
    profile["events"] += 1
    _save(identity_id, profile)

    assessment = {
        "identity_id": identity_id,
        "anomalous": bool(reasons),
        "reasons": reasons,
        "baseline_ready": baseline_ready,
        "risk_score": min(100.0, len(reasons) * 30.0),
    }
    if reasons:
        with session_scope() as db:
            db.add(
                Alert(
                    org_id=event.get("org_id", "unknown"),
                    module="machine_identity",
                    severity="high" if assessment["risk_score"] >= 60 else "medium",
                    title=f"Anomalous behaviour for identity {identity_id}",
                    body="; ".join(reasons),
                    context=assessment,
                )
            )
    return assessment


def profile_summary(identity_id: str) -> dict:
    p = _load(identity_id)
    return {
        "identity_id": identity_id,
        "events": p["events"],
        "distinct_ips": len(p["ips"]),
        "distinct_geos": len(p["geos"]),
        "top_resources": Counter(p["resources"]).most_common(5),
        "active_hours": sorted(int(h) for h in p["hours"]),
    }
