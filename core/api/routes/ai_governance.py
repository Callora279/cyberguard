"""AI Governance API: status, policy, audit log, fingerprints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal, require_admin
from core.database.db import session_scope
from core.database.models import AIPolicy
from core.services.ai_governance import audit
from core.services.ai_governance.ai_behavior_fingerprinting import (
    fingerprint_analyzer,
    fingerprint_store,
)
from core.services.ai_governance.real_time_enforcer import enforcement_status, guarded_chat

router = APIRouter()


class PolicyIn(BaseModel):
    name: str = "Default Policy"
    max_tokens: int = 4096
    allowed_models: list[str] = []
    prohibited_patterns: list[str] = []
    data_classification_rules: dict[str, str] = {}
    block_on_violation: bool = True


class ProxyChatIn(BaseModel):
    prompt: str
    system: str | None = None
    model: str | None = None
    max_tokens: int = 512
    purpose: str = "api_proxy"


@router.get("/status")
def status(principal: Principal = Depends(get_principal)) -> dict:
    return enforcement_status(principal.org_id)


@router.post("/policy")
def set_policy(body: PolicyIn, principal: Principal = Depends(require_admin)) -> dict:
    with session_scope() as db:
        db.query(AIPolicy).filter(AIPolicy.org_id == principal.org_id).update({"enabled": False})
        policy = AIPolicy(
            org_id=principal.org_id,
            name=body.name,
            max_tokens=body.max_tokens,
            allowed_models=body.allowed_models,
            prohibited_patterns=body.prohibited_patterns,
            data_classification_rules=body.data_classification_rules,
            block_on_violation=body.block_on_violation,
            enabled=True,
        )
        db.add(policy)
        db.flush()
        return {"id": policy.id, "name": policy.name, "enabled": True}


@router.get("/audit-log")
def audit_log(
    principal: Principal = Depends(get_principal),
    min_risk: float = 0.0,
    limit: int = Query(100, le=1000),
) -> dict:
    return {
        "entries": audit.audit_log(principal.org_id, limit=limit, min_risk=min_risk),
        "review_queue": audit.review_queue(principal.org_id),
    }


@router.get("/audit-log/{interaction_id}/explain")
def explain(interaction_id: str, principal: Principal = Depends(get_principal)) -> dict:
    return audit.explain(interaction_id)


@router.get("/compliance-export")
def compliance_export(fmt: str = "json", principal: Principal = Depends(require_admin)) -> dict:
    return {"format": fmt, "payload": audit.compliance_export(principal.org_id, fmt=fmt)}


@router.get("/fingerprints")
def fingerprints(principal: Principal = Depends(get_principal)) -> dict:
    return {
        "current": fingerprint_store.get_or_build(principal.org_id),
        "history": fingerprint_store.history(principal.org_id, limit=10),
        "drift": fingerprint_analyzer.drift_report(principal.org_id),
    }


@router.post("/proxy-chat")
def proxy_chat(body: ProxyChatIn, principal: Principal = Depends(get_principal)) -> dict:
    record = guarded_chat(
        body.prompt,
        org_id=principal.org_id,
        system=body.system,
        model=body.model,
        max_tokens=body.max_tokens,
        purpose=body.purpose,
    )
    return {
        "response": record.response,
        "model": record.model,
        "tokens": record.total_tokens,
        "cost_usd": record.cost_usd,
        "latency_ms": record.latency_ms,
        "policy_decision": record.metadata.get("policy_decision", "allow"),
        "risk_score": record.metadata.get("risk_score"),
    }
