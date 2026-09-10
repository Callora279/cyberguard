"""AI Fraud Detection API: analyze, alerts, risk-score."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal
from core.database.db import session_scope
from core.database.models import FraudAlert
from core.services.ai_fraud_detection import fraud_risk_scoring
from core.services.ai_fraud_detection.fusion_engine import fusion_analyzer, fusion_correlator
from core.utils.exceptions import NotFoundError

router = APIRouter()


class AnalyzeIn(BaseModel):
    type: str = "fusion"
    subject: str | None = None
    identity: dict | None = None
    transaction: dict = {}
    invoice: dict | None = None
    document: dict | None = None
    context: dict = {}
    history: list[dict] = []


class StatusIn(BaseModel):
    status: str


@router.post("/analyze")
def analyze(body: AnalyzeIn, principal: Principal = Depends(get_principal)) -> dict:
    case = {
        "case_id": body.subject or "case",
        "org_id": principal.org_id,
        "subject": body.subject,
        "identity": body.identity,
        "transaction": body.transaction,
        "invoice": body.invoice,
        "document": body.document,
        "context": body.context,
    }
    fused = fusion_analyzer.analyze_case(case, history=body.history)
    # persist as a fraud alert when material
    if fused["fused_fraud_score"] >= 40:
        with session_scope() as db:
            db.add(
                FraudAlert(
                    org_id=principal.org_id,
                    type=body.type,
                    subject=str(body.subject or ""),
                    risk_score=fused["fused_fraud_score"],
                    signals=fused["breakdown"],
                )
            )
    return fused


@router.get("/alerts")
def alerts(status: str | None = None, principal: Principal = Depends(get_principal)) -> dict:
    return {
        "alerts": fraud_risk_scoring.list_alerts(principal.org_id, status=status),
        "timeline": fusion_correlator.pattern_timeline(principal.org_id),
    }


@router.put("/alerts/{alert_id}")
def update_alert(alert_id: str, body: StatusIn, principal: Principal = Depends(get_principal)) -> dict:
    with session_scope() as db:
        a = db.get(FraudAlert, alert_id)
        if not a or a.org_id != principal.org_id:
            raise NotFoundError("fraud alert")
        a.status = body.status
        return {"id": a.id, "status": a.status}


@router.get("/risk-score")
def risk_score(principal: Principal = Depends(get_principal)) -> dict:
    return {
        "module_score": fraud_risk_scoring.module_score(principal.org_id),
        "open_alerts": len(fraud_risk_scoring.list_alerts(principal.org_id, status="open")),
    }
