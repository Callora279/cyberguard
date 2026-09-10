"""Combined fraud risk score across transaction, identity, document and behaviour."""
from __future__ import annotations

import re
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

# text-content combine weights (spec: invoice .35 / identity .25 / deepfake .25 / behavioural .15)
_CONTENT_WEIGHTS = {"invoice": 0.35, "identity": 0.25, "deepfake": 0.25, "behavioural": 0.15}

# (regex, friendly label, weight) — social-engineering / process-abuse cues in free text
_BEHAVIOURAL_PATTERNS: list[tuple[str, str, float]] = [
    (r"\bbypass(?:ing|ed)?\b", "asks to bypass a control", 0.25),
    (r"\bskip(?:ping)?\s+(?:the\s+)?(?:approval|process|checks?)\b", "asks to skip approval", 0.25),
    (r"\boutside\s+(?:the\s+)?normal\s+process\b", "explicitly outside normal process", 0.25),
    (r"\boverride\b", "requests an override", 0.20),
    (r"\bceo\b|\bcfo\b|\bchief\s+exec", "invokes executive authority", 0.20),
    (r"\burgent(?:ly)?\b", "urgency pressure", 0.15),
    (r"\bimmediat(?:e|ely)\b|\basap\b|\bright\s+away\b", "demands immediate action", 0.15),
    (r"within\s+\d+\s*(?:hours?|hrs?|business\s+days?)", "artificial deadline", 0.15),
    (r"\bconfidential(?:ly)?\b|do\s*n['o]?t\s+tell|keep\s+this\s+between", "secrecy request", 0.20),
    (r"gift\s*cards?|wire\s+transfer|crypto|bitcoin", "unusual payment channel", 0.20),
    (r"new\s+(?:bank|payment|account)\s+details|chang(?:e|ed|ing)\s+(?:the\s+)?bank", "bank-detail change", 0.25),
]


def _behavioural_content(content: str | None) -> dict:
    """Score social-engineering / pressure cues in a free-text message (0.0-1.0)."""
    low = (content or "").lower()
    reasons: list[str] = []
    score = 0.0
    for pattern, label, weight in _BEHAVIOURAL_PATTERNS:
        if re.search(pattern, low):
            reasons.append(label)
            score += weight
    return {"score": min(1.0, round(score, 3)), "reasons": reasons}


def _transaction_risk(txn: dict | None) -> tuple[float, list[str]]:
    txn = txn if isinstance(txn, dict) else {}
    reasons: list[str] = []
    score = 0.0
    amount = float(txn.get("amount", 0) or 0)
    if amount > float(txn.get("account_avg") or amount or 0) * 5:
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


def _behavioural_risk(ctx: dict | None) -> tuple[float, list[str]]:
    ctx = ctx if isinstance(ctx, dict) else {}
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
    payload: dict | None,
    *,
    org_id: str = "unknown",
    history: list[dict] | None = None,
    persist: bool = True,
) -> dict:
    """payload may contain: transaction, identity, document{text,meta}, context.

    Every sub-field is optional and may be ``None``; a fully empty/None payload
    scores 0 and returns an ``allow`` verdict rather than raising.
    """
    payload = payload if isinstance(payload, dict) else {}
    history = [h for h in (history or []) if isinstance(h, dict)]
    parts: dict[str, dict] = {}

    txn_s, txn_r = _transaction_risk(payload.get("transaction"))
    parts["transaction"] = {"score": txn_s, "reasons": txn_r}

    identity = payload.get("identity")
    id_result = (
        synthetic_identity.analyze(identity)
        if isinstance(identity, dict) and identity
        else {"synthetic_score": 0.0, "reasons": []}
    )
    parts["identity"] = {"score": id_result["synthetic_score"], "reasons": id_result["reasons"]}

    doc = payload.get("document")
    if isinstance(doc, dict) and doc:
        d = deepfake_detector.score_invoice_document(
            doc.get("text") or "", doc.get("meta") or {}, org_id=org_id
        )
        parts["document"] = {
            "score": d["document_risk_score"],
            "reasons": d["text_analysis"]["signals"].get("ai_phrase_markers", []),
        }
    else:
        parts["document"] = {"score": 0.0, "reasons": []}

    beh_s, beh_r = _behavioural_risk(payload.get("context"))
    parts["behavioural"] = {"score": beh_s, "reasons": beh_r}

    # optional invoice anomaly overlay
    invoice = payload.get("invoice")
    if isinstance(invoice, dict) and invoice:
        inv = invoice_anomaly.analyze(invoice, history)
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


def score_content(
    content: str | None,
    *,
    doc_type: str = "invoice",
    org_id: str = "unknown",
    persist: bool = True,
) -> dict:
    """Analyse a free-text document (invoice / payment request / vendor details).

    Runs all four text detectors and combines them on a 0.0-1.0 scale:
        invoice*0.35 + identity*0.25 + deepfake*0.25 + behavioural*0.15
    verdict: any component (or the blended score) > 0.9 -> block,
             > 0.7 (or blended >= 0.5) -> review, else allow.
    """
    text = content or ""

    inv = invoice_anomaly.analyze_content(text)
    ident = synthetic_identity.analyze_content(text)
    deep = deepfake_detector.analyze_content(text, org_id=org_id)
    beh = _behavioural_content(text)

    components = {
        "invoice": float(inv["score"]),
        "identity": float(ident["score"]),
        "deepfake": float(deep["fraud_score"]),
        "behavioural": float(beh["score"]),
    }
    fraud_score = round(sum(components[k] * w for k, w in _CONTENT_WEIGHTS.items()), 3)
    top = max(components.values(), default=0.0)

    if top > 0.9 or fraud_score >= 0.9:
        verdict = "block"
    elif top > 0.7 or fraud_score >= 0.5:
        verdict = "review"
    else:
        verdict = "allow"

    reasons = (
        [f"invoice: {r}" for r in inv["reasons"]]
        + [f"identity: {r}" for r in ident["reasons"]]
        + [f"document: {r}" for r in deep["reasons"]]
        + [f"behaviour: {r}" for r in beh["reasons"]]
    )

    result = {
        "type": doc_type,
        "fraud_score": fraud_score,
        "is_suspicious": fraud_score >= 0.5,
        "verdict": verdict,
        "reasons": reasons,
        "breakdown": {
            "invoice": {"score": components["invoice"], "reasons": inv["reasons"]},
            "identity": {"score": components["identity"], "reasons": ident["reasons"]},
            "deepfake": {
                "score": components["deepfake"],
                "reasons": deep["reasons"],
                "source": deep.get("source", "groq"),
            },
            "behavioural": {"score": components["behavioural"], "reasons": beh["reasons"]},
        },
        "weights": _CONTENT_WEIGHTS,
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }

    if persist and fraud_score >= 0.4:
        with session_scope() as db:
            db.add(
                FraudAlert(
                    org_id=org_id,
                    type=doc_type or "document",
                    subject=text.strip().splitlines()[0][:120] if text.strip() else "",
                    risk_score=round(fraud_score * 100, 1),  # stored on the 0-100 scale
                    signals=result["breakdown"],
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
