"""Transactional email via SendGrid (v3 Mail Send API), with SMTP fallback.

All failures are swallowed and logged — a notification must never break the
action that triggered it. ``send`` returns a small dict describing what happened.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage

import httpx

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("notifications.email")


def _send_via_sendgrid(to_addr: str, subject: str, html: str, text: str) -> dict:
    payload = {
        "personalizations": [{"to": [{"email": to_addr}]}],
        "from": {"email": settings.FROM_EMAIL, "name": "CyberGuard AI"},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": text or _strip_html(html)},
            {"type": "text/html", "value": html or f"<pre>{text}</pre>"},
        ],
    }
    try:
        r = httpx.post(
            settings.SENDGRID_API_URL,
            headers={
                "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=12.0,
        )
        r.raise_for_status()
        return {"sent": True, "transport": "sendgrid", "status": r.status_code}
    except httpx.HTTPError as exc:
        logger.warning("SendGrid send failed for %s: %s", to_addr, exc)
        return {"sent": False, "transport": "sendgrid", "error": str(exc)}


def _send_via_smtp(to_addr: str, subject: str, html: str, text: str) -> dict:
    if not settings.SMTP_HOST:
        return {"sent": False, "transport": "smtp", "error": "no SMTP_HOST"}
    try:
        msg = EmailMessage()
        msg["From"] = settings.FROM_EMAIL or settings.SMTP_FROM
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(text or _strip_html(html))
        if html:
            msg.add_alternative(html, subtype="html")
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as s:
            s.send_message(msg)
        return {"sent": True, "transport": "smtp"}
    except OSError as exc:
        logger.warning("SMTP send failed for %s: %s", to_addr, exc)
        return {"sent": False, "transport": "smtp", "error": str(exc)}


def send(to_addr: str, subject: str, *, html: str = "", text: str = "") -> dict:
    """Send one email. Prefers SendGrid, falls back to SMTP, else logs a no-op."""
    if not to_addr:
        return {"sent": False, "error": "no recipient"}

    if settings.SENDGRID_API_KEY:
        result = _send_via_sendgrid(to_addr, subject, html, text)
        if result["sent"]:
            logger.info("email '%s' -> %s via sendgrid", subject, to_addr)
            return result

    if settings.SMTP_HOST:
        result = _send_via_smtp(to_addr, subject, html, text)
        if result["sent"]:
            logger.info("email '%s' -> %s via smtp", subject, to_addr)
            return result

    logger.info("email not configured; would send '%s' to %s", subject, to_addr)
    return {"sent": False, "transport": "none", "error": "email not configured"}


def _strip_html(html: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", html or "").strip()
