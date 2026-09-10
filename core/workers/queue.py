"""Celery application (Redis broker + backend).

If Celery/Redis are not installed the module still imports; ``celery_app`` is
then ``None`` and callers fall back to synchronous execution.
"""
from __future__ import annotations

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("workers.queue")

try:
    from celery import Celery  # type: ignore

    celery_app = Celery(
        "cyberguard",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
    )
    celery_app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_track_started=True,
        task_time_limit=600,
        timezone="UTC",
    )
except Exception as exc:  # noqa: BLE001
    logger.warning("Celery unavailable (%s); tasks will run synchronously", exc)
    celery_app = None


def task(name: str):
    """Decorator that registers a Celery task when available, else passthrough."""

    def wrapper(fn):
        if celery_app is not None:
            return celery_app.task(name=name)(fn)
        fn.delay = lambda *a, **kw: fn(*a, **kw)  # type: ignore[attr-defined]
        return fn

    return wrapper
