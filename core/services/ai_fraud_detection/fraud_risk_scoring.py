"""Combined fraud risk score across transaction, identity, document and behaviour."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import FraudAlert
from core.services.ai_fraud_detection import (
    deepfake_detector,
    invoice_anomaly,
    synthetic_identity,
)

_WEIGHTS = {"transaction": 0.30, "identity": 0.25, "document": 0.25, "behavioural": 0.20}


def _transaction_risk(txn: dict) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    amount = float(txn.get("amount", 0))
    if amount > float(txn.get("account_avg", amount) or amount) * 5:
        score += 30
        reasons.append("transaction 5x account average")
    if txn.get("cross_border"):
        score += 15
        reasons.append("cross-border transfer")
    if txn.get("new_beneficiary"):
        score += 20
        reasons.append("new beneficiary")
    hour = txn.get("hour", datetime.now(timezone.utc).hour)
    if 0 <= hour < 5:
        score += 10
        reasons.append("overnight transaction")
    if txn.get("velocity_24h", 0) > 10:
        score += 15
        reasons.append("high transaction velocity")
    return min(100.0, score), reasons


def _behavioural_risk(ctx: dict) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    if ctx.get("device_change"):
        score += 20
        reasons.append("new device")
    if ctx.get("ip_country") and ctx.get("billing_country") and ctx["ip_country"] != ctx["billing_country"]:
        score += 20
        reasons.append("IP country != billing country")
    if ctx.get("failed_logins_24h", 0) >= 3:
        score += 15
        reasons.append("multiple recent failed logins")
    if ctx.get("session_age_seconds", 9999) < 30:
        score += 10
        reasons.append("action immediately after login")
    return min(100.0, score), reasons


def score(
    payload: dict,
    *,
    org_id: str = "unknown",
    history: list[dict] | None = None,
    persist: bool = True,
) -> dict:
    """payload may contain: transaction, identity, document{text,meta}, context."""
    parts: dict[str, dict] = {}

    txn_s, txn_r = _transaction_risk(payload.get("transaction", {}))
    parts["transaction"] = {"score": txn_s, "reasons": txn_r}

    id_result = synthetic_identity.analyze(payload["identity"]) if payload.get("identity") else {"synthetic_score": 0.0, "reasons": []}
    parts["identity"] = {"score": id_result["synthetic_score"], "reasons": id_result["reasons"]}

    doc = payload.get("document")
    if doc:
        d = deepfake_detector.score_invoice_document(
            doc.get("text", ""), doc.get("meta", {}), org_id=org_id
        )
        parts["document"] = {"score": d["document_risk_score"], "reasons": d["text_analysis"]["signals"].get("ai_phrase_markers", [])}
    else:
        parts["document"] = {"score": 0.0, "reasons": []}

    beh_s, beh_r = _behavioural_risk(payload.get("context", {}))
    parts["behavioural"] = {"score": beh_s, "reasons": beh_r}

    # optional invoice anomaly overlay
    if payload.get("invoice"):
        inv = invoice_anomaly.analyze(payload["invoice"], history)
        parts["document"]["score"] = max(parts["document"]["score"], inv["anomaly_score"])
        parts["document"]["reasons"] += inv["reasons"]

    overall = round(sum(parts[k]["score"] * w for k, w in _WEIGHTS.items()), 1)
    verdict = "block" if overall >= 70 else ("review" if overall >= 40 else "allow")
    result = {
        "org_id": org_id,
        "overall_fraud_score": overall,
        "verdict": verdict,
        "breakdown": parts,
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }

    if persist and overall >= 40:
        with session_scope() as db:
            db.add(
                FraudAlert(
                    org_id=org_id,
                    type=payload.get("type", "fusion"),
                    subject=str(payload.get("subject") or payload.get("identity", {}).get("email", "")),
                    risk_score=overall,
                    signals=parts,
                    status="open",
                )
            )
    return result


def list_alerts(org_id: str, *, status: str | None = None) -> list[dict]:
    with session_scope() as db:
        stmt = select(FraudAlert).where(FraudAlert.org_id == org_id)
        if status:
            stmt = stmt.where(FraudAlert.status == status)
        rows = db.scalars(stmt.order_by(FraudAlert.created_at.desc())).all()
        return [
            {
                "id": r.id, "type": r.type, "subject": r.subject, "risk_score": r.risk_score,
                "status": r.status, "signals": r.signals, "created_at": r.created_at,
            }
            for r in rows
        ]


def module_score(org_id: str) -> float:
    """0-100 health score (higher = less fraud risk)."""
    alerts = list_alerts(org_id, status="open")
    if not alerts:
        return 100.0
    penalty = sum(a["risk_score"] for a in alerts) / len(alerts)
    return round(max(0.0, 100.0 - penalty), 2)
