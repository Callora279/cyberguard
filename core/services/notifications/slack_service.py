"""Post Block Kit messages to an incoming-webhook URL. Never raises."""
from __future__ import annotations

import httpx

from core.utils.logger import get_logger

logger = get_logger("notifications.slack")


def send_blocks(webhook_url: str | None, blocks: list[dict], *, fallback_text: str = "CyberGuard alert") -> dict:
    if not webhook_url:
        logger.info("slack webhook not configured; skipping: %s", fallback_text)
        return {"sent": False, "error": "no webhook url"}
    try:
        r = httpx.post(
            webhook_url,
            json={"text": fallback_text, "blocks": blocks},
            timeout=8.0,
        )
        r.raise_for_status()
        return {"sent": True, "status": r.status_code}
    except httpx.HTTPError as exc:
        logger.warning("slack post failed: %s", exc)
        return {"sent": False, "error": str(exc)}


def send_text(webhook_url: str | None, text: str) -> dict:
    if not webhook_url:
        logger.info("slack webhook not configured; skipping: %s", text)
        return {"sent": False, "error": "no webhook url"}
    try:
        r = httpx.post(webhook_url, json={"text": text}, timeout=8.0)
        r.raise_for_status()
        return {"sent": True, "status": r.status_code}
    except httpx.HTTPError as exc:
        logger.warning("slack post failed: %s", exc)
        return {"sent": False, "error": str(exc)}
