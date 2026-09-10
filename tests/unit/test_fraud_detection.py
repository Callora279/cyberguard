from core.services.ai_fraud_detection import invoice_anomaly, synthetic_identity
from core.services.ai_fraud_detection.fusion_engine import fusion_analyzer


def test_synthetic_identity_flags_disposable_email():
    r = synthetic_identity.analyze(
        {"email": "user8391@mailinator.com", "phone": "0000000000", "full_name": "Test User"}
    )
    assert r["synthetic_score"] >= 35
    assert r["verdict"] in ("synthetic", "suspicious")


def test_genuine_identity_passes():
    r = synthetic_identity.analyze(
        {"email": "priya.sharma@acme.co.uk", "phone": "+447911123456",
         "full_name": "Priya Sharma", "address": {"line1": "12 King St", "postcode": "EC1A 1BB", "country": "GB"}}
    )
    assert r["verdict"] == "genuine"


def test_invoice_anomaly_detects_duplicate_and_round():
    history = [{"id": "A", "vendor": "Acme", "amount": 5000.0}]
    r = invoice_anomaly.analyze(
        {"id": "B", "vendor": "Acme", "amount": 5000.0, "date": "2026-09-06"}, history
    )
    assert r["anomaly_score"] > 0
    assert any("duplicate" in reason for reason in r["reasons"])


def test_fusion_amplifies_multi_signal(org_id):
    case = {
        "case_id": "c1",
        "org_id": org_id,
        "identity": {"email": "x9999@mailinator.com", "phone": "0000000000"},
        "transaction": {"amount": 90000, "account_avg": 3000, "new_beneficiary": True, "cross_border": True},
        "context": {"ip_country": "NG", "billing_country": "GB", "device_change": True},
    }
    r = fusion_analyzer.analyze_case(case)
    assert r["fused_fraud_score"] >= r["base_score"]
    assert r["verdict"] in ("review", "block")
