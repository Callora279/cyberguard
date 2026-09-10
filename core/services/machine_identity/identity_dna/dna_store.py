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
