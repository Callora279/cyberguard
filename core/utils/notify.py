"""Multi-channel alert delivery: DB alert row + Slack webhook + email.

Every module raises operational alerts through :func:`send_alert` so the
delivery channels (which are configured per-org in ``org_settings``) live in one
place. Channel failures never propagate — a missing Slack webhook or SMTP host
must not break a scan or a scheduled sweep.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage

import httpx

from core.database.db import session_scope
from core.database.models import Alert, OrgSettings
from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("utils.notify")

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _channels(org_id: str) -> tuple[str | None, str | None, str]:
    with session_scope() as db:
        row = db.get(OrgSettings, org_id)
        if not row:
            return None, None, "high"
        return row.slack_webhook_url, row.report_email, row.alert_threshold or "high"


def _post_slack(webhook: str, text: str) -> bool:
    try:
        r = httpx.post(webhook, json={"text": text}, timeout=8.0)
        r.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.warning("slack notify failed: %s", exc)
        return False


def _send_email(to_addr: str, subject: str, body: str) -> bool:
    if not settings.SMTP_HOST:
        logger.info("email notify skipped (no SMTP_HOST): would send '%s' to %s", subject, to_addr)
        return False
    try:
        msg = EmailMessage()
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as s:
            s.send_message(msg)
        return True
    except OSError as exc:
        logger.warning("email notify failed: %s", exc)
        return False


def send_alert(
    org_id: str,
    *,
    module: str,
    severity: str,
    title: str,
    body: str = "",
    context: dict | None = None,
) -> dict:
    """Persist an Alert row and fan out to Slack / email when above threshold."""
    with session_scope() as db:
        alert = Alert(
            org_id=org_id,
            module=module,
            severity=severity,
            title=title,
            body=body,
            context=context or {},
        )
        db.add(alert)
        db.flush()
        alert_id = alert.id

    slack, email, threshold = _channels(org_id)
    delivered = {"db": True, "slack": False, "email": False}
    if _SEVERITY_ORDER.get(severity, 1) >= _SEVERITY_ORDER.get(threshold, 2):
        text = f"[{severity.upper()}] {title}\n{body}".strip()
        if slack:
            delivered["slack"] = _post_slack(slack, f":rotating_light: *CyberGuard* {text}")
        if email:
            delivered["email"] = _send_email(email, f"CyberGuard alert: {title}", text)

    logger.info("alert %s (%s/%s) delivered=%s", alert_id, module, severity, delivered)
    return {"alert_id": alert_id, "delivered": delivered}
