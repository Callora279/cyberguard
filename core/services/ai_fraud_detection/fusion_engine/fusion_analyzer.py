"""Fuse signals from every fraud detector into a single assessment."""
from __future__ import annotations

from core.services.ai_fraud_detection import fraud_risk_scoring
from core.services.ai_fraud_detection.fusion_engine import fusion_correlator
from core.utils.logger import get_logger

logger = get_logger("fraud.fusion_analyzer")

# a "case" bundles everything known about one suspected fraud event
# {case_id, org_id, identity, transaction, invoice, document, context}


def analyze_case(case: dict | None, *, history: list[dict] | None = None) -> dict:
    case = case if isinstance(case, dict) else {}
    org_id = case.get("org_id") or "unknown"
    # drop any None entries a caller may have passed in the history list
    history = [h for h in (history or []) if isinstance(h, dict)]

    base = fraud_risk_scoring.score(
        {
            "identity": case.get("identity"),
            "transaction": case.get("transaction") or {},
            "invoice": case.get("invoice"),
            "document": case.get("document"),
            "context": case.get("context") or {},
            "type": "fusion",
            "subject": case.get("subject"),
        },
        org_id=org_id,
        history=history,
        persist=False,
    )

    # cross-signal amplification: multiple independent detectors agreeing is
    # much stronger evidence than any single one. Detector results may be missing
    # or None if a detector failed — treat those as "not firing".
    breakdown = base.get("breakdown") or {}
    firing = [k for k, v in breakdown.items() if (v or {}).get("score", 0.0) >= 40]
    amplification = 0.0
    if len(firing) >= 3:
        amplification = 15.0
    elif len(firing) == 2:
        amplification = 8.0

    correlation = fusion_correlator.correlate(org_id, case, base)
    amplification += correlation.get("boost", 0.0)

    fused = min(100.0, base.get("overall_fraud_score", 0.0) + amplification)
    verdict = "block" if fused >= 70 else ("review" if fused >= 40 else "allow")

    result = {
        "case_id": case.get("case_id"),
        "org_id": org_id,
        "fused_fraud_score": round(fused, 1),
        "base_score": base.get("overall_fraud_score", 0.0),
        "amplification": round(amplification, 1),
        "verdict": verdict,
        "firing_detectors": firing,
        "breakdown": breakdown,
        "correlation": correlation,
    }
    logger.info("fusion case %s -> %s (%.1f)", case.get("case_id"), verdict, fused)
    return result
