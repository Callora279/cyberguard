"""Slack bot: real-time alerts, /cyberguard command, daily digest."""
from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx

from core.database.db import session_scope
from core.database.models import Alert, Organisation
from core.services.security_debt import reporting as debt_reporting
from core.services.supply_chain import alerts as sc_alerts
from core.services.unified_risk_score import score_calculator
from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("agents.slack")

_SEVERITY_EMOJI = {"critical": ":rotating_light:", "high": ":red_circle:", "medium": ":large_orange_circle:", "low": ":large_yellow_circle:", "info": ":information_source:"}
_DEFAULT_PATH = os.getenv("SCAN_TARGET_PATH", ".")


class SlackBot:
    def __init__(self, token: str | None = None, webhook_url: str | None = None) -> None:
        self.token = token or settings.SLACK_BOT_TOKEN
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")

    def _post(self, text: str, blocks: list | None = None, channel: str = "#security") -> dict:
        payload = {"text": text, "channel": channel}
        if blocks:
            payload["blocks"] = blocks
        try:
            if self.webhook_url:
                r = httpx.post(self.webhook_url, json=payload, timeout=10.0)
            elif self.token:
                r = httpx.post(
                    "https://slack.com/api/chat.postMessage",
                    headers={"Authorization": f"Bearer {self.token}"},
                    json=payload,
                    timeout=10.0,
                )
            else:
                logger.info("slack not configured; message:\n%s", text)
                return {"ok": False, "reason": "not configured"}
            return {"ok": r.status_code == 200}
        except httpx.HTTPError as exc:
            logger.warning("slack post failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    # ---- alert push ----------------------------------------------------
    def notify_alert(self, alert: dict) -> dict:
        emoji = _SEVERITY_EMOJI.get(alert.get("severity", "info"), ":shield:")
        return self._post(
            f"{emoji} *[{alert.get('severity', 'info').upper()}] {alert.get('title')}*\n"
            f"Module: `{alert.get('module')}`\n{alert.get('body', '')}"
        )

    def incident_notification(self, title: str, detail: str) -> dict:
        return self._post(f":fire: *INCIDENT: {title}*\n{detail}", channel="#incidents")

    # ---- slash command ----------------------------------------------
    def handle_command(self, text: str, org_id: str) -> dict:
        parts = text.strip().split()
        cmd = parts[0] if parts else "help"
        if cmd == "scan":
            debt = debt_reporting.run_scan(org_id, _DEFAULT_PATH)
            supply = sc_alerts.run_scan(org_id, _DEFAULT_PATH)
            return {
                "response_type": "in_channel",
                "text": (
                    f":mag: *Scan complete*\n"
                    f"• Security debt: {debt['total_findings']} findings "
                    f"({debt['by_severity'].get('critical', 0)} critical)\n"
                    f"• Dependencies: {supply['vulnerable_components']} vulnerable, "
                    f"{supply['critical_or_high']} high/critical CVEs"
                ),
            }
        if cmd == "score":
            r = score_calculator.calculate(org_id)
            return {"response_type": "in_channel", "text": f":bar_chart: Unified risk score: *{r['overall']}* (grade {r['grade']})"}
        return {
            "response_type": "ephemeral",
            "text": "Usage: `/cyberguard scan` | `/cyberguard score`",
        }

    # ---- daily digest ----------------------------------------------
    def daily_digest(self, org_id: str) -> dict:
        with session_scope() as db:
            org = db.get(Organisation, org_id)
            recent = db.query(Alert).filter(
                Alert.org_id == org_id, Alert.acknowledged.is_(False)
            ).order_by(Alert.created_at.desc()).limit(10).all()
            lines = [f"• {_SEVERITY_EMOJI.get(a.severity, '')} [{a.module}] {a.title}" for a in recent]
        score = score_calculator.calculate(org_id)
        text = (
            f":sunrise: *CyberGuard daily digest — {org.name if org else org_id}*\n"
            f"Risk score: *{score['overall']}* ({score['grade']})\n"
            f"Open alerts: {len(lines)}\n" + ("\n".join(lines) if lines else "_No open alerts_")
        )
        return self._post(text)


def broadcast_new_alerts(org_id: str, since: datetime | None = None) -> int:
    since = since or datetime.now(timezone.utc)
    bot = SlackBot()
    sent = 0
    with session_scope() as db:
        rows = db.query(Alert).filter(
            Alert.org_id == org_id, Alert.created_at >= since, Alert.severity.in_(("critical", "high"))
        ).all()
        for a in rows:
            bot.notify_alert({"severity": a.severity, "title": a.title, "module": a.module, "body": a.body})
            sent += 1
    return sent
