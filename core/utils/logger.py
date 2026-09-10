"""Structured logging helper with optional LiveGuard error forwarding."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

import httpx

from core.utils.config import settings

_configured = False


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)


def report_to_liveguard(error: str, severity: str = "error") -> None:
    """Best-effort forward of an error to LiveGuard. Never raises."""
    if settings.ENV == "test":
        return
    try:
        httpx.post(
            settings.LIVEGUARD_URL,
            json={
                "app": "cyberguard",
                "error": error,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            timeout=3.0,
        )
    except Exception:  # noqa: BLE001 - telemetry must not break the app
        get_logger("liveguard").warning("failed to forward error to liveguard")
