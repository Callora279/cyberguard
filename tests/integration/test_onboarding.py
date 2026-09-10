"""Onboarding + settings API integration tests."""
from __future__ import annotations

import pytest


@pytest.fixture()
def fresh_headers(client, unique_email, mock_credentials):
    """Register a brand-new trial org and return its auth headers."""

    def _make(org_name: str | None = None):
        r = client.post(
            "/api/auth/register",
            json={
                "email": unique_email("onb"),
                "password": mock_credentials["password"],
                "org_name": org_name or mock_credentials["org_name"],
                "start_trial": True,
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["plan"] == "trial"
        assert body["onboarding_completed"] is False
        return {"Authorization": f"Bearer {body['access_token']}"}

    return _make


def test_onboarding_status_starts_incomplete(fresh_headers, client):
    h = fresh_headers()
    st = client.get("/api/onboarding/status", headers=h).json()
    assert st["completed"] is False
    assert st["current_step"] == 1
    assert st["total_steps"] == 4
    assert len(st["steps"]) == 4


def test_skip_advances_step(fresh_headers, client):
    h = fresh_headers()
    st = client.post("/api/onboarding/skip", headers=h, json={"step": 1}).json()
    assert st["current_step"] == 2


def test_alert_config_and_complete(fresh_headers, client):
    h = fresh_headers()
    report_email = "security@example.com"
    st = client.post(
        "/api/onboarding/alerts",
        headers=h,
        json={"report_email": report_email, "alert_threshold": "high"},
    ).json()
    assert any(s["key"] == "alerts" and s["done"] for s in st["steps"])

    done = client.post("/api/onboarding/complete", headers=h).json()
    assert done["completed"] is True

    settings = client.get("/api/settings", headers=h).json()
    assert settings["alerts"]["report_email"] == report_email
    # slack webhook / token are masked, not returned raw
    assert settings["alerts"]["slack_webhook_url"] in (None, "")


def test_billing_reports_trial(fresh_headers, client):
    h = fresh_headers()
    b = client.get("/api/settings/billing", headers=h).json()
    assert b["plan"] == "trial"
    assert b["trial_days_left"] is not None
    assert b["limits"]["repos"] == 3


def test_api_token_lifecycle(fresh_headers, client):
    h = fresh_headers()
    created = client.post("/api/settings/api-tokens", headers=h, json={"name": "ci"}).json()
    assert created["token"].startswith("cgcli_")
    listed = client.get("/api/settings/api-tokens", headers=h).json()["tokens"]
    assert len(listed) == 1 and listed[0]["name"] == "ci"
    # full token is never returned again
    assert "token" not in listed[0]
    client.delete(f"/api/settings/api-tokens/{created['id']}", headers=h)
    assert client.get("/api/settings/api-tokens", headers=h).json()["tokens"] == []


def test_license_key_grants_pro(client, unique_email, mock_credentials):
    r = client.post(
        "/api/auth/register",
        json={
            "email": unique_email("licensed"),
            "password": mock_credentials["password"],
            "org_name": mock_credentials["org_name"],
            "license_key": mock_credentials["license_key"],
            "start_trial": False,
        },
    )
    assert r.status_code == 200
    assert r.json()["plan"] == "pro"


def test_website_scan_produces_findings(fresh_headers, client):
    h = fresh_headers()
    r = client.post("/api/onboarding/website", headers=h, json={"url": "https://example.com"})
    assert r.status_code == 200
    body = r.json()
    assert "report" in body
    assert 0 <= body["report"]["score"] <= 100
    assert body["report"]["checks_run"] > 0
