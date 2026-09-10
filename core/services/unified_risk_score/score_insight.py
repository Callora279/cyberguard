"""Groq-generated narrative insight for the unified risk score.

Turns the numeric breakdown + raw signals into a short executive summary a CISO
can paste into a board update. Deterministic fallback when the LLM is
unavailable so the dashboard always has something to show.
"""
from __future__ import annotations

from core.services.ai_governance.real_time_enforcer import guarded_chat
from core.utils.exceptions import CyberGuardError
from core.utils.logger import get_logger

logger = get_logger("unified_risk.insight")


def _fallback(result: dict) -> str:
    breakdown = result.get("breakdown", {})
    weakest = sorted(breakdown.items(), key=lambda kv: kv[1])[:2]
    parts = ", ".join(f"{m.replace('_', ' ')} ({s:.0f}/100)" for m, s in weakest)
    return (
        f"Overall posture is {result.get('overall')}/100 (grade {result.get('grade')}). "
        f"The weakest areas are {parts}. Prioritise remediation there to move the grade."
    )


def generate(result: dict, *, org_id: str = "unknown") -> dict:
    """``result`` is a ``score_calculator.calculate`` payload."""
    prompt = (
        "You are a CISO briefing the board. In <=110 words, summarise this security "
        "posture: name the overall grade, call out the 2 weakest modules and what "
        "their raw signals imply, and give one concrete next step. Plain prose, no "
        "markdown, no preamble.\n\n"
        f"overall={result.get('overall')} grade={result.get('grade')}\n"
        f"breakdown={result.get('breakdown')}\n"
        f"signals={result.get('signals')}"
    )
    try:
        summary = guarded_chat(
            prompt,
            org_id=org_id,
            system="Be concise, factual, executive tone.",
            purpose="risk_score_insight",
            max_tokens=260,
        ).response.strip()
        source = "ai"
    except CyberGuardError as exc:
        logger.warning("risk insight LLM call failed: %s", exc)
        summary, source = _fallback(result), "fallback"

    return {"summary": summary, "source": source}
