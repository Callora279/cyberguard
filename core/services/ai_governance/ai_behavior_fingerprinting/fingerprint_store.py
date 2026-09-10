"""Persist and retrieve AI behaviour fingerprints.

Backed by Redis when available, otherwise a JSON file under ``.cyberguard/``.
Keeps the most recent fingerprint per org plus a short history.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("ai_governance.fingerprint_store")

_DIR = Path(os.getenv("CYBERGUARD_STATE_DIR", ".cyberguard")) / "fingerprints"
_HISTORY = 20

try:  # optional redis
    import redis  # type: ignore

    _redis = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
    _redis.ping()
except Exception:  # noqa: BLE001
    _redis = None


def _key(org_id: str) -> str:
    return f"cg:fingerprint:{org_id}"


def save(org_id: str, fingerprint: dict) -> None:
    payload = json.dumps(fingerprint, default=str)
    if _redis is not None:
        _redis.set(_key(org_id), payload)
        _redis.lpush(f"{_key(org_id)}:history", payload)
        _redis.ltrim(f"{_key(org_id)}:history", 0, _HISTORY - 1)
        return
    _DIR.mkdir(parents=True, exist_ok=True)
    (_DIR / f"{org_id}.json").write_text(payload)
    hist_path = _DIR / f"{org_id}.history.jsonl"
    with hist_path.open("a") as fh:
        fh.write(payload + "\n")


def latest(org_id: str) -> dict | None:
    if _redis is not None:
        raw = _redis.get(_key(org_id))
        return json.loads(raw) if raw else None
    path = _DIR / f"{org_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def history(org_id: str, limit: int = _HISTORY) -> list[dict]:
    if _redis is not None:
        return [json.loads(x) for x in _redis.lrange(f"{_key(org_id)}:history", 0, limit - 1)]
    path = _DIR / f"{org_id}.history.jsonl"
    if not path.exists():
        return []
    lines = path.read_text().strip().splitlines()[-limit:]
    return [json.loads(x) for x in lines]


def get_or_build(org_id: str, *, max_age_seconds: int = 3600) -> dict:
    from core.services.ai_governance.ai_behavior_fingerprinting import fingerprint_generator

    current = latest(org_id)
    if current:
        try:
            age = time.time() - _iso_to_epoch(current["generated_at"])
            if age < max_age_seconds:
                return current
        except Exception:  # noqa: BLE001
            pass
    fresh = fingerprint_generator.generate(org_id)
    save(org_id, fresh)
    return fresh


def _iso_to_epoch(value: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(value).timestamp()
