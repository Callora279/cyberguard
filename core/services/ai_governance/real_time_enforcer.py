"""Real-time enforcement proxy for AI API calls.

``guarded_chat`` is the entrypoint the rest of CyberGuard (and the AI-usage
agent) should use instead of calling ``ai_client.chat`` directly: it evaluates
policy *before* the call, blocks non-compliant requests, runs the call, and
lets the monitor observer record + alert.
"""
from __future__ import annotations

from typing import Any

from core.services.ai_governance import monitor, policy_engine, risk_scoring
from core.services.ai_governance.ai_behavior_fingerprinting import fingerprint_analyzer
from core.utils.ai_client import AICallRecord, chat
from core.utils.config import settings
from core.utils.crypto import sha256_hex
from core.utils.exceptions import PolicyViolation
from core.utils.logger import get_logger

logger = get_logger("ai_governance.enforcer")

# Pre-call block gate: if the normalised prompt-risk (0-1) is at or above this,
# the request never reaches Groq — it is blocked, alerted and logged.
RISK_BLOCK_THRESHOLD = 0.8

_installed = False


def install() -> None:
    global _installed
    if _installed:
        return
    monitor.install()
    _installed = True


def guarded_chat(
    prompt: str,
    *,
    org_id: str,
    system: str | None = None,
    model: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.2,
    purpose: str = "generic",
) -> AICallRecord:
    install()
    model = model or settings.GROQ_MODEL

    decision = policy_engine.evaluate(
        org_id, prompt=prompt, model=model, max_tokens=max_tokens
    )
    logger.info(
        "policy decision for org=%s purpose=%s -> %s %s",
        org_id, purpose, decision.action, decision.violations,
    )
    if not decision.allowed:
        # still record the blocked attempt for the audit trail
        _record_blocked(prompt, org_id, model, decision.violations)
        raise PolicyViolation(
            "AI request blocked by governance policy",
            details={"violations": decision.violations},
        )

    # Pre-call risk gate — block obviously dangerous prompts (injection +
    # exfiltration + PII exposure) before they ever reach the model.
    risk = risk_scoring.prompt_risk(prompt)
    if risk >= RISK_BLOCK_THRESHOLD:
        violations = [f"pre-call risk score {risk:.2f} >= {RISK_BLOCK_THRESHOLD}"]
        logger.warning("blocking org=%s purpose=%s on risk=%.2f", org_id, purpose, risk)
        _record_blocked(prompt, org_id, model, violations, risk=risk)
        raise PolicyViolation(
            "AI request blocked: prompt risk score above threshold",
            details={"risk_score": risk, "violations": violations},
        )

    record = chat(
        prompt,
        system=system,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        metadata={
            "org_id": org_id,
            "purpose": purpose,
            "policy_decision": decision.action,
        },
    )

    record.metadata.setdefault("pre_call_risk", risk)
    record.metadata["risk_score"] = risk_scoring.score_interaction(
        prompt, record.response
    ).score

    anomaly = fingerprint_analyzer.check(org_id, record)
    if anomaly.get("anomalous"):
        logger.warning("fingerprint anomaly for org=%s: %s", org_id, anomaly["reasons"])
    return record


def _record_blocked(
    prompt: str, org_id: str, model: str, violations: list[str], *, risk: float | None = None
) -> None:
    meta = {"org_id": org_id, "policy_decision": "block", "violations": violations}
    if risk is not None:
        meta["pre_call_risk"] = risk
    fake = AICallRecord(
        model=model,
        prompt=prompt,
        prompt_hash=sha256_hex(prompt),
        response="",
        prompt_tokens=0,
        completion_tokens=0,
        total_tokens=0,
        latency_ms=0.0,
        cost_usd=0.0,
        metadata=meta,
    )
    try:
        monitor.record_interaction(fake)
    except Exception:  # noqa: BLE001
        logger.exception("failed to record blocked interaction")


def enforcement_status(org_id: str) -> dict[str, Any]:
    policy = policy_engine.load_policy(org_id)
    return {
        "installed": _installed,
        "active_policy": {
            "id": policy.id,
            "name": policy.name,
            "max_tokens": policy.max_tokens,
            "allowed_models": policy.allowed_models,
            "prohibited_pattern_count": len(policy.prohibited_patterns),
            "data_classification_rules": policy.data_classification_rules,
            "block_on_violation": policy.block_on_violation,
        },
        "usage": monitor.usage_summary(org_id),
    }
