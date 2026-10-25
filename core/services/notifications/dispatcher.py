"""Route notification events to the channels an org has configured.

One entrypoint per event type. Each looks up the org's ``OrgSettings``, decides
which channels apply, renders via :mod:`templates`, and sends. Delivery failures
are logged, never raised.
"""
from __future__ import annotations

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, OrgSettings, Organisation
from core.services.notifications import email_service, slack_service, templates
from core.utils.logger import get_logger

logger = get_logger("notifications.dispatcher")

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ctx(org_id: str) -> dict:
    with session_scope() as db:
        row = db.get(OrgSettings, org_id)
        org = db.get(Organisation, org_id)
        return {
            "org_name": org.name if org else org_id,
            "slack_webhook": (row.slack_webhook_url if row else None),
            "slack_daily_digest": bool(row and row.slack_daily_digest),
            "email": (row.notification_email or row.report_email) if row else None,
            "notify_types": list(row.notify_types or []) if row else [],
            "weekly_digest": bool(row.weekly_digest) if row else True,
            "threshold": (row.alert_threshold if row else "high") or "high",
            "last_notified_score": (row.last_notified_score if row else None),
        }


def _email_enabled(ctx: dict, event: str) -> bool:
    if not ctx["email"]:
        return False
    types = ctx["notify_types"]
    return not types or event in types


def _record_score(org_id: str, score: float) -> None:
    with session_scope() as db:
        row = db.get(OrgSettings, org_id)
        if row:
            row.last_notified_score = score


# --------------------------------------------------------------------------- #
def notify_critical_finding(org_id: str, finding: dict) -> dict:
    ctx = _ctx(org_id)
    out = {"email": None, "slack": None}
    if _email_enabled(ctx, "critical_finding"):
        t = templates.critical_alert_email(finding)
        out["email"] = email_service.send(ctx["email"], t["subject"], html=t["html"], text=t["text"])
    if ctx["slack_webhook"]:
        out["slack"] = slack_service.send_blocks(
            ctx["slack_webhook"],
            templates.critical_finding_blocks(finding),
            fallback_text="Critical security finding",
        )
    logger.info("notify critical_finding org=%s -> %s", org_id, out)
    return out


def notify_fraud_alert(org_id: str, fraud: dict) -> dict:
    """Fraud alerts fire when fraud_score > 0.7 (caller's responsibility)."""
    ctx = _ctx(org_id)
    out = {"email": None, "slack": None}
    if _email_enabled(ctx, "fraud_alert"):
        t = templates.fraud_alert_email(fraud)
        out["email"] = email_service.send(ctx["email"], t["subject"], html=t["html"], text=t["text"])
    if ctx["slack_webhook"]:
        blocks = (
            templates.fraud_blocked_blocks(fraud)
            if fraud.get("verdict") == "block"
            else templates.critical_finding_blocks(
                {"title": "Fraud risk detected", "description": ", ".join(fraud.get("reasons", [])[:3]),
                 "recommendation": f"Verdict: {fraud.get('verdict')} · score {fraud.get('fraud_score', 0):.2f}"}
            )
        )
        out["slack"] = slack_service.send_blocks(
            ctx["slack_webhook"], blocks, fallback_text="Fraud risk detected"
        )
    logger.info("notify fraud_alert org=%s -> %s", org_id, out)
    return out


def notify_credential_expiring(org_id: str, cred: dict) -> dict:
    ctx = _ctx(org_id)
    out = {"email": None, "slack": None}
    if _email_enabled(ctx, "credential_expiring"):
        t = templates.credential_expiring_email(cred)
        out["email"] = email_service.send(ctx["email"], t["subject"], html=t["html"], text=t["text"])
    if ctx["slack_webhook"]:
        out["slack"] = slack_service.send_blocks(
            ctx["slack_webhook"],
            templates.credential_expiring_blocks(cred),
            fallback_text="Credential expiring soon",
        )
    return out


def notify_risk_change(org_id: str, before: float, after: float) -> dict:
    """Slack on any change > 10 points; email on a significant drop."""
    ctx = _ctx(org_id)
    delta = round(after - before, 1)
    out = {"email": None, "slack": None, "delta": delta}
    if abs(delta) < 10:
        return out
    if ctx["slack_webhook"]:
        out["slack"] = slack_service.send_blocks(
            ctx["slack_webhook"],
            templates.risk_change_blocks(before, after, ctx["org_name"]),
            fallback_text=f"Risk score changed {delta:+}",
        )
    if delta <= -10 and _email_enabled(ctx, "risk_drop"):
        t = templates.risk_drop_email(before, after, ctx["org_name"])
        out["email"] = email_service.send(ctx["email"], t["subject"], html=t["html"], text=t["text"])
    _record_score(org_id, after)
    return out


def notify_weekly_digest(org_id: str) -> dict:
    from core.services.security_debt import reporting as debt_reporting
    from core.services.unified_risk_score import score_calculator

    ctx = _ctx(org_id)
    if not (ctx["weekly_digest"] and ctx["email"]):
        return {"skipped": "weekly digest not enabled / no email"}

    score = score_calculator.calculate(org_id, persist=False)
    summary = debt_reporting.summary(org_id)
    digest = {
        "org_name": ctx["org_name"],
        "score": score["overall"],
        "grade": score["grade"],
        "top_findings": summary.get("top_10", [])[:8],
        "improvements": [
            f"{m.replace('_', ' ')}: {round(s, 1)}/100"
            for m, s in sorted(score["breakdown"].items(), key=lambda kv: kv[1], reverse=True)[:3]
        ],
    }
    t = templates.weekly_digest_email(digest)
    return {"email": email_service.send(ctx["email"], t["subject"], html=t["html"], text=t["text"])}


def notify_daily_summary(org_id: str) -> dict:
    from core.services.unified_risk_score import score_calculator

    ctx = _ctx(org_id)
    if not (ctx["slack_daily_digest"] and ctx["slack_webhook"]):
        return {"skipped": "daily summary not enabled"}

    score = score_calculator.calculate(org_id, persist=False)
    with session_scope() as db:
        rows = db.scalars(
            select(Alert)
            .where(Alert.org_id == org_id, Alert.acknowledged.is_(False))
            .order_by(Alert.created_at.desc())
            .limit(10)
        ).all()
        open_alerts = [{"module": a.module, "severity": a.severity, "title": a.title} for a in rows]
    blocks = templates.daily_summary_blocks(
        {
            "org_name": ctx["org_name"],
            "score": score["overall"],
            "grade": score["grade"],
            "open_count": len(open_alerts),
            "open_alerts": open_alerts,
        }
    )
    return {"slack": slack_service.send_blocks(ctx["slack_webhook"], blocks, fallback_text="Daily summary")}


def route_alert(org_id: str, alert: dict) -> None:
    """Best-effort bridge from ``core.utils.notify.send_alert`` — Slack only, and
    only for alerts at/above the org threshold. Email for these generic alerts is
    handled by the typed events above."""
    ctx = _ctx(org_id)
    severity = alert.get("severity", "info")
    if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(ctx["threshold"], 2):
        return
    if not ctx["slack_webhook"]:
        return
    slack_service.send_blocks(
        ctx["slack_webhook"],
        templates.critical_finding_blocks(
            {
                "title": alert.get("title"),
                "description": alert.get("title"),
                "recommendation": alert.get("body", ""),
                "file": alert.get("module", ""),
            }
        ),
        fallback_text=alert.get("title", "CyberGuard alert"),
    )
