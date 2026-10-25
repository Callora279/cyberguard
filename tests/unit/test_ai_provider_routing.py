"""Every AI-generating module must route through core.services.ai_client
(org-aware) rather than calling guarded_chat directly — otherwise an org's
configured provider (OpenAI/Anthropic/Gemini/custom) is silently ignored and
the system-default Groq key is used instead."""
from __future__ import annotations

from unittest.mock import patch

from core.services import ai_client
from core.utils.ai_client import AICallRecord


def _fake_record(response: str, *, provider: str = "openai", model: str = "gpt-4o-mini") -> AICallRecord:
    return AICallRecord(
        model=model, prompt="", prompt_hash="", response=response,
        prompt_tokens=1, completion_tokens=1, total_tokens=2,
        latency_ms=1.0, cost_usd=0.0, metadata={"provider": provider},
    )


def test_remediation_assistant_routes_through_org_client():
    from core.services.security_debt import remediation_assistant

    payload = '{"explanation": "e", "recommended_fix": "f", "code_example": "c", "estimated_fix_minutes": 5, "references": []}'
    with patch.object(ai_client, "chat_for_org", return_value=_fake_record(payload)) as mock_chat:
        result = remediation_assistant.suggest({"type": "secret", "id": "f1"}, org_id="org-1")
    mock_chat.assert_called_once()
    assert mock_chat.call_args.args[0] == "org-1"
    assert result["source"] == "ai"
    assert result["provider"] == "openai"


def test_deepfake_detector_routes_through_org_client():
    from core.services.ai_fraud_detection import deepfake_detector

    payload = '{"fraud_score": 0.9, "is_suspicious": true, "reasons": ["x"]}'
    with patch.object(ai_client, "chat_for_org", return_value=_fake_record(payload)) as mock_chat:
        result = deepfake_detector.analyze_content("some vendor invoice text " * 5, org_id="org-2")
    mock_chat.assert_called_once()
    assert mock_chat.call_args.args[0] == "org-2"
    assert result["source"] == "openai"


def test_score_insight_routes_through_org_client():
    from core.services.unified_risk_score import score_insight

    with patch.object(ai_client, "chat_for_org", return_value=_fake_record("Board summary.")) as mock_chat:
        result = score_insight.generate({"overall": 80, "grade": "B", "breakdown": {}, "signals": {}}, org_id="org-3")
    mock_chat.assert_called_once()
    assert mock_chat.call_args.args[0] == "org-3"
    assert result["source"] == "ai"
    assert result["provider"] == "openai"


def test_sbom_ai_supplement_routes_through_org_client(tmp_path):
    from core.services.supply_chain.ai_generated_sbom import sbom_generator

    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN pip install foo\n")
    payload = '{"components": [{"name": "python", "version": "3.12", "type": "container"}]}'
    with patch.object(ai_client, "chat_for_org", return_value=_fake_record(payload)) as mock_chat:
        doc = sbom_generator.generate(tmp_path, use_ai=True, org_id="org-4")
    mock_chat.assert_called_once()
    assert mock_chat.call_args.args[0] == "org-4"
    assert any(c["name"] == "python" for c in doc["components"])
