from core.services.ai_fraud_detection import invoice_anomaly, synthetic_identity
from core.services.ai_fraud_detection.fusion_engine import fusion_analyzer


def test_synthetic_identity_flags_disposable_email(fraud_test_vectors):
    r = synthetic_identity.analyze(
        {
            "email": fraud_test_vectors["disposable_email"],
            "phone": fraud_test_vectors["placeholder_phone"],
            "full_name": "Mock User",
        }
    )
    assert r["synthetic_score"] >= 35
    assert r["verdict"] in ("synthetic", "suspicious")


def test_genuine_identity_passes(fraud_test_vectors):
    r = synthetic_identity.analyze(
        {
            "email": fraud_test_vectors["genuine_email"],
            "phone": fraud_test_vectors["genuine_phone"],
            "full_name": fraud_test_vectors["genuine_name"],
            "address": fraud_test_vectors["genuine_address"],
        }
    )
    assert r["verdict"] == "genuine"


def test_invoice_anomaly_detects_duplicate_and_round():
    history = [{"id": "A", "vendor": "Acme", "amount": 5000.0}]
    r = invoice_anomaly.analyze(
        {"id": "B", "vendor": "Acme", "amount": 5000.0, "date": "2026-09-06"}, history
    )
    assert r["anomaly_score"] > 0
    assert any("duplicate" in reason for reason in r["reasons"])


def test_fraud_detectors_never_crash_on_none():
    # Issue 1: None / missing fields must degrade to safe defaults, not raise.
    assert synthetic_identity.analyze(None)["verdict"] == "genuine"
    assert invoice_anomaly.analyze(None, None)["anomaly_score"] == 0.0
    r = fusion_analyzer.analyze_case(None, history=[None, {"id": "x"}])
    assert r["verdict"] == "allow"
    assert r["fused_fraud_score"] == 0.0
    r2 = fusion_analyzer.analyze_case({"identity": None, "context": None, "invoice": None})
    assert r2["verdict"] == "allow"


def test_fusion_amplifies_multi_signal(org_id, fraud_test_vectors):
    case = {
        "case_id": "c1",
        "org_id": org_id,
        "identity": {
            "email": fraud_test_vectors["disposable_email"],
            "phone": fraud_test_vectors["placeholder_phone"],
        },
        "transaction": {"amount": 90000, "account_avg": 3000, "new_beneficiary": True, "cross_border": True},
        "context": {"ip_country": "NG", "billing_country": "GB", "device_change": True},
    }
    r = fusion_analyzer.analyze_case(case)
    assert r["fused_fraud_score"] >= r["base_score"]
    assert r["verdict"] in ("review", "block")
