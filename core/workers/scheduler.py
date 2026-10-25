"""Celery beat schedule + a threaded fallback scheduler for dev without Celery."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Organisation
from core.utils.logger import get_logger
from core.workers import background_tasks
from core.workers.queue import celery_app

logger = get_logger("workers.scheduler")

# interval jobs — (task_name -> seconds)
SCHEDULE = {
    "recalculate_risk": 21_600,      # every 6 hours   (Phase 2 spec)
    "check_new_cves": 3_600,          # every 1 hour    (Phase 2 spec)
    "rotate_due_credentials": 3_600,
    "refresh_fingerprint": 1_800,
}
# daily jobs — (task_name -> UTC hour)
DAILY_AT = {
    "daily_identity_sweep": 0,        # 00:00 — check expiring credentials
    "send_daily_digest": 8,           # 08:00 — daily Slack digest
}
# weekly jobs — (task_name -> (weekday 0=Mon, UTC hour))
WEEKLY_AT = {
    "send_weekly_report": (0, 9),     # Monday 09:00 — weekly security report
}

if celery_app is not None:  # register with celery beat
    from celery.schedules import crontab

    celery_app.conf.beat_schedule = {
        "recalc-risk-6h": {
            "task": "cyberguard.recalculate_risk",
            "schedule": 21_600.0,
            "options": {"expires": 3_600},
        },
        "check-new-cves-hourly": {
            "task": "cyberguard.check_new_cves",
            "schedule": 3_600.0,
        },
        "rotate-credentials-hourly": {
            "task": "cyberguard.rotate_due_credentials",
            "schedule": 3_600.0,
        },
        "refresh-fingerprint-30m": {
            "task": "cyberguard.refresh_fingerprint",
            "schedule": 1_800.0,
        },
        "identity-sweep-daily-midnight": {
            "task": "cyberguard.daily_identity_sweep",
            "schedule": crontab(hour=0, minute=0),
        },
        "daily-digest-0800": {
            "task": "cyberguard.send_daily_digest",
            "schedule": crontab(hour=8, minute=0),
        },
        "weekly-report-monday-0900": {
            "task": "cyberguard.send_weekly_report",
            "schedule": crontab(hour=9, minute=0, day_of_week=1),
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

    def _run_for_all(self, task_name: str) -> None:
        fn = getattr(background_tasks, task_name)
        for org_id in _all_org_ids():
            try:
                fn(org_id)
            except Exception:  # noqa: BLE001
                logger.exception("scheduled task %s failed for %s", task_name, org_id)
        logger.info("ran %s at %s", task_name, datetime.now(timezone.utc).isoformat())

    def _loop(self, task_name: str, interval: int) -> None:
        while not self._stop.wait(interval):
            self._run_for_all(task_name)

    def _calendar_loop(self, task_name: str, hour: int, weekday: int | None = None) -> None:
        """Fire once per day (or per week) at ``hour`` UTC."""
        while not self._stop.is_set():
            now = datetime.now(timezone.utc)
            nxt = now.replace(hour=hour, minute=0, second=0, microsecond=0)
            if nxt <= now:
                nxt += timedelta(days=1)
            if weekday is not None:
                while nxt.weekday() != weekday:
                    nxt += timedelta(days=1)
            if self._stop.wait((nxt - now).total_seconds()):
                return
            self._run_for_all(task_name)

    def start(self) -> None:
        for name, interval in SCHEDULE.items():
            t = threading.Thread(target=self._loop, args=(name, interval), daemon=True)
            t.start()
            self._threads.append(t)
        for name, hour in DAILY_AT.items():
            t = threading.Thread(target=self._calendar_loop, args=(name, hour), daemon=True)
            t.start()
            self._threads.append(t)
        for name, (weekday, hour) in WEEKLY_AT.items():
            t = threading.Thread(target=self._calendar_loop, args=(name, hour, weekday), daemon=True)
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
