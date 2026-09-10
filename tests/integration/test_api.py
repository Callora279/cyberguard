"""API integration tests against an in-process TestClient + SQLite."""
from __future__ import annotations

from core.utils.config import settings


def test_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["checks"]["database"] == "ok"


def test_auth_required(client):
    assert client.get("/api/risk-score/current").status_code == 401


def test_register_and_login(client, mock_credentials):
    r = client.post(
        "/api/auth/register",
        json={
            "email": mock_credentials["email"],
            "password": mock_credentials["password"],
            "org_name": mock_credentials["org_name"],
        },
    )
    assert r.status_code == 200
    token = r.json()["access_token"]
    me = client.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["email"] == mock_credentials["email"]


def test_security_debt_scan_flow(client, auth_headers, tmp_path, mock_secret_token):
    (tmp_path / "app.py").write_text(
        f"API_KEY = '{mock_secret_token}'\nimport pickle\npickle.loads(b'')\n"
    )
    res = client.post(
        "/api/security-debt/scan",
        headers=auth_headers,
        json={"path": str(tmp_path), "include_dependencies": False},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total_findings"] >= 2
    assert body["by_severity"].get("critical", 0) >= 1


def test_risk_score_and_chakra_endpoint(client, auth_headers):
    res = client.get("/api/risk-score/current", headers=auth_headers)
    assert res.status_code == 200
    assert 0 <= res.json()["overall"] <= 100

    chakra = client.get(
        "/internal/health-score",
        params={"chakra_org_id": settings.CHAKRA_ORG_ID},
        headers={"X-Sync-Secret": settings.INTERNAL_SYNC_SECRET},
    )
    assert chakra.status_code == 200
    assert "security_score" in chakra.json()


def test_chakra_endpoint_rejects_bad_secret(client):
    res = client.get(
        "/internal/health-score",
        params={"chakra_org_id": "x"},
        headers={"X-Sync-Secret": "wrong"},
    )
    assert res.status_code == 401


def test_alerts_list_and_ack(client, auth_headers):
    res = client.get("/api/alerts", headers=auth_headers)
    assert res.status_code == 200
    assert "alerts" in res.json()


def test_cyber_twin_build_and_simulate(client, auth_headers):
    build = client.post("/api/cyber-twin/build", headers=auth_headers, json={"path": "core"})
    assert build.status_code == 200
    sim = client.post("/api/cyber-twin/simulate", headers=auth_headers, json={"scenario": "owasp_top_10"})
    assert sim.status_code == 200
    assert "twin_risk_score" in sim.json()
