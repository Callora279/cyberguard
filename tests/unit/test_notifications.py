"""Phase 2 — notification templates + dispatcher routing."""
from __future__ import annotations

import pytest

from core.services.notifications import dispatcher, email_service, slack_service, templates


# --- templates --------------------------------------------------------- #
def test_critical_alert_email_has_subject_and_link():
    t = templates.critical_alert_email(
        {"title": "Hardcoded API key", "file_path": "app.py", "line": 45, "recommendation": "Rotate it"}
    )
    assert t["subject"] == "🔴 Critical Security Alert — CyberGuard AI"
    assert "app.py:45" in t["text"]
    assert "Rotate it" in t["html"]


def test_fraud_alert_email_includes_score_and_reasons():
    t = templates.fraud_alert_email({"fraud_score": 0.86, "verdict": "block", "reasons": ["bypass", "urgent"]})
    assert "0.86" in t["subject"]
    assert "block" in t["html"]
    assert "bypass" in t["html"]


def test_slack_blocks_shape_is_block_kit():
    blocks = templates.critical_finding_blocks(
        {"title": "SQLi", "file_path": "db.py", "line": 89, "recommendation": "Parameterise"}
    )
    assert blocks[0]["type"] == "header"
    assert blocks[1]["type"] == "section"
    assert blocks[2]["type"] == "actions"
    assert blocks[2]["elements"][0]["url"].startswith("http")


def test_weekly_digest_email_lists_findings():
    t = templates.weekly_digest_email(
        {"org_name": "Acme", "score": 72, "grade": "B",
         "top_findings": [{"title": "X", "severity": "high", "file_path": "a.py"}],
         "improvements": ["supply chain: 90/100"]}
    )
    assert "Weekly Security Report — Acme" in t["subject"]
    assert "X" in t["html"]


# --- transports degrade gracefully ----------------------------------- #
def test_email_service_noop_when_unconfigured(monkeypatch):
    monkeypatch.setattr(email_service.settings, "SENDGRID_API_KEY", "", raising=False)
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "", raising=False)
    r = email_service.send("someone@example.com", "hi", text="body")
    assert r["sent"] is False


def test_slack_service_noop_without_webhook():
    assert slack_service.send_blocks(None, [])["sent"] is False
    assert slack_service.send_text("", "hi")["sent"] is False


def test_email_service_uses_sendgrid_when_key_present(monkeypatch):
    calls = {}

    class _Resp:
        status_code = 202
        def raise_for_status(self): pass

    def _post(url, **kw):
        calls["url"] = url
        calls["json"] = kw["json"]
        return _Resp()

    monkeypatch.setattr(email_service.settings, "SENDGRID_API_KEY", "SG.test", raising=False)
    monkeypatch.setattr(email_service.httpx, "post", _post)
    r = email_service.send("dev@example.com", "Subject", html="<b>hi</b>", text="hi")
    assert r == {"sent": True, "transport": "sendgrid", "status": 202}
    assert calls["url"].endswith("/v3/mail/send")
    assert calls["json"]["personalizations"][0]["to"][0]["email"] == "dev@example.com"


# --- dispatcher routing --------------------------------------------- #
def test_dispatcher_fraud_alert_hits_configured_channels(org_id, monkeypatch, client):
    sent = {"slack": 0, "email": 0}

    monkeypatch.setattr(dispatcher.slack_service, "send_blocks",
                        lambda *a, **k: sent.__setitem__("slack", sent["slack"] + 1) or {"sent": True})
    monkeypatch.setattr(dispatcher.email_service, "send",
                        lambda *a, **k: sent.__setitem__("email", sent["email"] + 1) or {"sent": True})

    from core.database.db import session_scope
    from core.database.models import OrgSettings

    with session_scope() as db:
        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        row.slack_webhook_url = "https://hooks.slack.com/services/T/B/x"
        row.notification_email = "sec@example.com"
        row.notify_types = []

    dispatcher.notify_fraud_alert(org_id, {"fraud_score": 0.9, "verdict": "block", "reasons": ["r1"]})
    assert sent["slack"] == 1 and sent["email"] == 1


def test_dispatcher_risk_change_ignores_small_delta(org_id, monkeypatch):
    monkeypatch.setattr(dispatcher.slack_service, "send_blocks", lambda *a, **k: pytest.fail("should not send"))
    out = dispatcher.notify_risk_change(org_id, 80.0, 84.0)  # +4, below the 10-point gate
    assert out["slack"] is None
