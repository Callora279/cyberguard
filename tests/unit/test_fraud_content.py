"""Text-content fraud detection: the 4 detectors score raw strings, not just dicts."""
from __future__ import annotations

import pytest

from core.services.ai_fraud_detection import (
    deepfake_detector,
    fraud_risk_scoring,
    invoice_anomaly,
    synthetic_identity,
)


@pytest.fixture()
def stub_deepfake(monkeypatch):
    """Keep the combine tests offline — deepfake calls Groq otherwise."""

    def _fake(content, *, org_id="unknown"):
        score = 0.8 if content and "bypass" in content.lower() else 0.05
        return {"fraud_score": score, "is_suspicious": score >= 0.5, "reasons": ["stubbed"], "source": "stub"}

    monkeypatch.setattr(deepfake_detector, "analyze_content", _fake)

SUSPICIOUS_INVOICE = (
    "Invoice #1234\n"
    "Vendor: NEW COMPANY LTD\n"
    "Amount: £50000\n"
    "Pay urgently within 24 hours\n"
    "CEO approved bypass normal process"
)


def test_invoice_anomaly_reads_text_content():
    r = invoice_anomaly.analyze_content(SUSPICIOUS_INVOICE)
    assert 0.0 <= r["score"] <= 1.0
    assert r["score"] >= 0.7
    joined = " ".join(r["reasons"]).lower()
    assert "round amount" in joined
    assert "10,000" in joined
    assert "bypass" in joined and "ceo" in joined
    assert "24-hour" in joined


def test_invoice_anomaly_late_night_and_pay_immediately():
    r = invoice_anomaly.analyze_content("Payment run at 23:47. Please pay immediately.")
    reasons = " ".join(r["reasons"]).lower()
    assert "out-of-hours" in reasons
    assert "immediate" in reasons
    assert r["score"] > 0


def test_synthetic_identity_reads_text_content():
    r = synthetic_identity.analyze_content(SUSPICIOUS_INVOICE)
    assert 0.0 <= r["score"] <= 1.0
    reasons = " ".join(r["reasons"]).lower()
    assert "registration" in reasons  # missing company number
    assert "generic" in reasons or "placeholder" in reasons  # NEW COMPANY LTD
    assert "contact" in reasons  # no email/phone/address


def test_synthetic_identity_flags_repeated_digit_bank_details():
    r = synthetic_identity.analyze_content(
        "Acme Trading Ltd\nSort code: 99-99-99\nAccount: 99999999"
    )
    assert any("repeated digit" in x.lower() for x in r["reasons"])
    assert r["score"] > 0


def test_synthetic_identity_empty_text_is_zero():
    assert synthetic_identity.analyze_content("")["score"] == 0.0
    assert invoice_anomaly.analyze_content(None)["score"] == 0.0


def test_score_content_combines_and_blocks(stub_deepfake):
    r = fraud_risk_scoring.score_content(SUSPICIOUS_INVOICE, doc_type="invoice", persist=False)
    assert r["fraud_score"] > 0.5
    assert r["is_suspicious"] is True
    assert r["verdict"] in ("review", "block")
    assert set(r["breakdown"]) == {"invoice", "identity", "deepfake", "behavioural"}
    assert r["weights"] == {"invoice": 0.35, "identity": 0.25, "deepfake": 0.25, "behavioural": 0.15}
    # weighted arithmetic is internally consistent
    expected = round(
        sum(r["breakdown"][k]["score"] * w for k, w in r["weights"].items()), 3
    )
    assert abs(r["fraud_score"] - expected) < 1e-6


def test_score_content_benign_text_allows(stub_deepfake):
    r = fraud_risk_scoring.score_content(
        "Hi, attached is our Q2 statement of work as agreed on last week's call. "
        "Payment terms net-30 as per the signed MSA. Regards, Accounts, "
        "billing@vendor-corp.example, +44 20 7946 1234.",
        persist=False,
    )
    assert r["fraud_score"] < 0.5
    assert r["verdict"] == "allow"
