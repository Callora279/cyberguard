"""End-to-end: scan -> findings -> unified score -> forecast -> alert ack."""
from __future__ import annotations


def test_full_platform_flow(client, auth_headers, tmp_path, mock_secret_token, fraud_test_vectors):
    # 1. a small vulnerable project
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    (tmp_path / "svc.py").write_text(
        "import os\n"
        f"SECRET = '{mock_secret_token}'\n"
        "os.system('echo ' + input())\n"
    )

    # 2. security-debt scan
    debt = client.post(
        "/api/security-debt/scan",
        headers=auth_headers,
        json={"path": str(tmp_path), "include_dependencies": False},
    ).json()
    assert debt["total_findings"] >= 1

    # 3. heatmap reflects the scan
    hm = client.get("/api/security-debt/heatmap", headers=auth_headers).json()
    assert hm["files"]

    # 4. unified risk score recalculated
    score = client.get("/api/risk-score/current", headers=auth_headers).json()
    assert score["grade"] in {"A+", "A", "B", "C", "D", "F"}

    # 5. predictive forecast produced
    forecast = client.get(
        "/api/risk-score/forecast?horizon_days=30", headers=auth_headers
    ).json()
    assert forecast["incident_forecast"]["predictions"]

    # 6. fraud analysis end to end
    fraud = client.post(
        "/api/fraud-detection/analyze",
        headers=auth_headers,
        json={
            "subject": "e2e-case",
            "identity": {
                "email": fraud_test_vectors["disposable_email"],
                "phone": fraud_test_vectors["placeholder_phone"],
            },
            "transaction": {"amount": 75000, "account_avg": 2000, "new_beneficiary": True},
            "context": {"ip_country": "RU", "billing_country": "GB", "device_change": True},
        },
    ).json()
    assert fraud["verdict"] in {"allow", "review", "block"}

    # 7. an alert exists and can be acknowledged
    alerts = client.get("/api/alerts", headers=auth_headers).json()["alerts"]
    if alerts:
        ack = client.put(f"/api/alerts/{alerts[0]['id']}/acknowledge", headers=auth_headers)
        assert ack.status_code == 200
        assert ack.json()["acknowledged"] is True
