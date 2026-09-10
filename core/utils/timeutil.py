"""Datetime helpers that keep SQLite (naive) and PostgreSQL (aware) consistent."""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_aware(dt: datetime | None) -> datetime | None:
    """Coerce a possibly-naive datetime (as SQLite returns) to UTC-aware."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
