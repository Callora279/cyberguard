"""Celery beat schedule + a threaded fallback scheduler for dev without Celery."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Organisation
from core.utils.logger import get_logger
from core.workers import background_tasks
from core.workers.queue import celery_app

logger = get_logger("workers.scheduler")

# (task_name, interval_seconds)
SCHEDULE = {
    "recalculate_risk": 900,
    "rotate_due_credentials": 3600,
    "refresh_fingerprint": 1800,
}

if celery_app is not None:  # register with celery beat
    from celery.schedules import crontab  # noqa: F401

    celery_app.conf.beat_schedule = {
        "recalc-risk-15m": {
            "task": "cyberguard.recalculate_risk",
            "schedule": 900.0,
            "args": (),
            "options": {"expires": 600},
        },
        "rotate-credentials-hourly": {
            "task": "cyberguard.rotate_due_credentials",
            "schedule": 3600.0,
        },
        "refresh-fingerprint-30m": {
            "task": "cyberguard.refresh_fingerprint",
            "schedule": 1800.0,
        },
    }


def _all_org_ids() -> list[str]:
    with session_scope() as db:
        return [o.id for o in db.scalars(select(Organisation)).all()]


class ThreadedScheduler:
    """Minimal in-process scheduler used when Celery beat is not running."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def _loop(self, task_name: str, interval: int) -> None:
        fn = getattr(background_tasks, task_name)
        while not self._stop.wait(interval):
            for org_id in _all_org_ids():
                try:
                    fn(org_id) if task_name != "full_org_sweep" else None
                except Exception:  # noqa: BLE001
                    logger.exception("scheduled task %s failed for %s", task_name, org_id)
            logger.info("ran %s at %s", task_name, datetime.now(timezone.utc).isoformat())

    def start(self) -> None:
        for name, interval in SCHEDULE.items():
            t = threading.Thread(target=self._loop, args=(name, interval), daemon=True)
            t.start()
            self._threads.append(t)
        logger.info("threaded scheduler started with %d jobs", len(self._threads))

    def stop(self) -> None:
        self._stop.set()


_scheduler: ThreadedScheduler | None = None


def start_threaded_scheduler() -> ThreadedScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ThreadedScheduler()
        _scheduler.start()
    return _scheduler


if __name__ == "__main__":
    start_threaded_scheduler()
    while True:
        time.sleep(60)
