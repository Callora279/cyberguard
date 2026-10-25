"""Store and retrieve identity DNA profiles (Redis or JSON file fallback)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from core.utils.config import settings

_DIR = Path(os.getenv("CYBERGUARD_STATE_DIR", ".cyberguard")) / "identity_dna"

try:
    import redis  # type: ignore

    _redis = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
    _redis.ping()
except Exception:  # noqa: BLE001
    _redis = None


def _key(identity_id: str) -> str:
    return f"cg:dna:{identity_id}"


def save(identity_id: str, dna: dict) -> None:
    payload = json.dumps(dna, default=str)
    if _redis is not None:
        _redis.set(_key(identity_id), payload)
        return
    _DIR.mkdir(parents=True, exist_ok=True)
    (_DIR / f"{identity_id}.json").write_text(payload)


def load(identity_id: str) -> dict | None:
    if _redis is not None:
        raw = _redis.get(_key(identity_id))
        return json.loads(raw) if raw else None
    path = _DIR / f"{identity_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def all_ids() -> list[str]:
    if _redis is not None:
        return [k.decode().split(":")[-1] for k in _redis.scan_iter("cg:dna:*")]
    if not _DIR.exists():
        return []
    return [p.stem for p in _DIR.glob("*.json")]


# ---------------------------------------------------------------------------
# Raw access-event log + behavioural fingerprint (Phase 3). Kept separate from
# the strand-based DNA above: events are timestamped so the fingerprint can be
# windowed to "last 7 days" as specified, rather than the all-time EWMA the
# strand vector uses.
# ---------------------------------------------------------------------------
_EVENTS_DIR = Path(os.getenv("CYBERGUARD_STATE_DIR", ".cyberguard")) / "identity_dna_events"
_MAX_EVENTS = 5000  # ring-buffer cap per identity


def _events_key(identity_id: str) -> str:
    return f"cg:dna_events:{identity_id}"


def _fp_key(identity_id: str) -> str:
    return f"cg:dna_fp:{identity_id}"


def append_event(identity_id: str, event: dict) -> None:
    """Append one access event: {ts, hour, endpoint, ip}. Ring-buffered."""
    if _redis is not None:
        pipe = _redis.pipeline()
        pipe.rpush(_events_key(identity_id), json.dumps(event, default=str))
        pipe.ltrim(_events_key(identity_id), -_MAX_EVENTS, -1)
        pipe.execute()
        return
    _EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    path = _EVENTS_DIR / f"{identity_id}.json"
    events = json.loads(path.read_text()) if path.exists() else []
    events.append(event)
    if len(events) > _MAX_EVENTS:
        events = events[-_MAX_EVENTS:]
    path.write_text(json.dumps(events, default=str))


def load_events(identity_id: str) -> list[dict]:
    if _redis is not None:
        return [json.loads(raw) for raw in _redis.lrange(_events_key(identity_id), 0, -1)]
    path = _EVENTS_DIR / f"{identity_id}.json"
    return json.loads(path.read_text()) if path.exists() else []


def save_fingerprint(identity_id: str, fingerprint: dict) -> None:
    payload = json.dumps(fingerprint, default=str)
    if _redis is not None:
        _redis.set(_fp_key(identity_id), payload)
        return
    _EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    (_EVENTS_DIR / f"{identity_id}.fingerprint.json").write_text(payload)


def load_fingerprint(identity_id: str) -> dict | None:
    if _redis is not None:
        raw = _redis.get(_fp_key(identity_id))
        return json.loads(raw) if raw else None
    path = _EVENTS_DIR / f"{identity_id}.fingerprint.json"
    return json.loads(path.read_text()) if path.exists() else None
