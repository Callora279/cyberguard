"""Audit trail, explainability, human review queue and compliance export."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import AIInteraction
from core.utils.ai_client import chat
from core.utils.logger import get_logger

logger = get_logger("ai_governance.audit")


def audit_log(org_id: str, *, limit: int = 100, min_risk: float = 0.0) -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(
            select(AIInteraction)
            .where(AIInteraction.org_id == org_id, AIInteraction.risk_score >= min_risk)
            .order_by(AIInteraction.timestamp.desc())
            .limit(limit)
        ).all()
        return [_row_to_dict(r) for r in rows]


def review_queue(org_id: str, *, risk_threshold: float = 50.0) -> list[dict]:
    """Interactions that need a human decision."""
    with session_scope() as db:
        rows = db.scalars(
            select(AIInteraction)
            .where(
                AIInteraction.org_id == org_id,
                AIInteraction.reviewed.is_(False),
                (AIInteraction.risk_score >= risk_threshold)
                | (AIInteraction.policy_decision != "allow"),
            )
            .order_by(AIInteraction.risk_score.desc())
        ).all()
        return [_row_to_dict(r) for r in rows]


def resolve_review(interaction_id: str, *, decision: str, note: str = "") -> dict:
    with session_scope() as db:
        row = db.get(AIInteraction, interaction_id)
        if not row:
            raise KeyError(interaction_id)
        row.reviewed = True
        row.risk_breakdown = {**(row.risk_breakdown or {}), "review": {"decision": decision, "note": note}}
        return _row_to_dict(row)


def explain(interaction_id: str) -> dict:
    """Generate a plain-language explainability report for one AI decision."""
    with session_scope() as db:
        row = db.get(AIInteraction, interaction_id)
        if not row:
            raise KeyError(interaction_id)
        snapshot = _row_to_dict(row)

    try:
        summary = chat(
            "You are an AI governance auditor. In <=120 words explain, for a "
            "compliance officer, why this AI interaction received its risk score "
            "and whether the automated decision looks correct.\n\n"
            f"{json.dumps(snapshot, default=str)}",
            system="Be concise, factual, no markdown.",
            metadata={"org_id": snapshot["org_id"], "purpose": "audit_explain"},
            max_tokens=300,
        ).response
    except Exception as exc:  # noqa: BLE001
        logger.warning("explainability LLM call failed: %s", exc)
        summary = (
            f"Risk score {snapshot['risk_score']} driven by "
            f"{snapshot.get('risk_breakdown')}. Automated decision: "
            f"{snapshot['policy_decision']}."
        )
    return {"interaction": snapshot, "explanation": summary}


def compliance_export(org_id: str, *, fmt: str = "json") -> str:
    """Export the full audit trail as evidence (JSON or CSV string)."""
    rows = audit_log(org_id, limit=100_000)
    generated = datetime.now(timezone.utc).isoformat()
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "id", "timestamp", "model", "prompt_hash", "total_tokens",
                "cost_usd", "risk_score", "policy_decision", "reviewed",
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k) for k in writer.fieldnames})
        return buf.getvalue()
    return json.dumps(
        {"org_id": org_id, "generated_at": generated, "interactions": rows},
        default=str,
        indent=2,
    )


def _row_to_dict(r: AIInteraction) -> dict:
    return {
        "id": r.id,
        "org_id": r.org_id,
        "timestamp": r.timestamp,
        "model": r.model,
        "prompt_hash": r.prompt_hash,
        "prompt_preview": r.prompt_preview,
        "response_preview": r.response_preview,
        "prompt_tokens": r.prompt_tokens,
        "completion_tokens": r.completion_tokens,
        "total_tokens": r.total_tokens,
        "cost_usd": r.cost_usd,
        "latency_ms": r.latency_ms,
        "risk_score": r.risk_score,
        "risk_breakdown": r.risk_breakdown,
        "policy_decision": r.policy_decision,
        "reviewed": r.reviewed,
    }
