"""Fuse signals from every fraud detector into a single assessment."""
from __future__ import annotations

from core.services.ai_fraud_detection import fraud_risk_scoring
from core.services.ai_fraud_detection.fusion_engine import fusion_correlator
from core.utils.logger import get_logger

logger = get_logger("fraud.fusion_analyzer")

# a "case" bundles everything known about one suspected fraud event
# {case_id, org_id, identity, transaction, invoice, document, context}


def analyze_case(case: dict, *, history: list[dict] | None = None) -> dict:
    org_id = case.get("org_id", "unknown")
    base = fraud_risk_scoring.score(
        {
            "identity": case.get("identity"),
            "transaction": case.get("transaction", {}),
            "invoice": case.get("invoice"),
            "document": case.get("document"),
            "context": case.get("context", {}),
            "type": "fusion",
            "subject": case.get("subject"),
        },
        org_id=org_id,
        history=history,
        persist=False,
    )

    # cross-signal amplification: multiple independent detectors agreeing is
    # much stronger evidence than any single one.
    firing = [k for k, v in base["breakdown"].items() if v["score"] >= 40]
    amplification = 0.0
    if len(firing) >= 3:
        amplification = 15.0
    elif len(firing) == 2:
        amplification = 8.0

    correlation = fusion_correlator.correlate(org_id, case, base)
    amplification += correlation.get("boost", 0.0)

    fused = min(100.0, base["overall_fraud_score"] + amplification)
    verdict = "block" if fused >= 70 else ("review" if fused >= 40 else "allow")

    result = {
        "case_id": case.get("case_id"),
        "org_id": org_id,
        "fused_fraud_score": round(fused, 1),
        "base_score": base["overall_fraud_score"],
        "amplification": round(amplification, 1),
        "verdict": verdict,
        "firing_detectors": firing,
        "breakdown": base["breakdown"],
        "correlation": correlation,
    }
    logger.info("fusion case %s -> %s (%.1f)", case.get("case_id"), verdict, fused)
    return result
