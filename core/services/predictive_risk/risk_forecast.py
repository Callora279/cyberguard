"""30 / 60 / 90 day risk forecast with proactive recommendations."""
from __future__ import annotations

from datetime import datetime, timezone

from core.services.predictive_risk import predictor, trend_analyzer
from core.services.unified_risk_score import score_model

_HORIZONS = (30, 60, 90)

_PLAYBOOKS = {
    "supply_chain_attack": [
        "Pin and verify all dependency hashes; enable lockfile CI checks",
        "Regenerate and diff the SBOM on every merge",
        "Subscribe critical packages to advisory alerts",
    ],
    "credential_compromise": [
        "Force rotation of credentials older than 90 days",
        "Enforce MFA / step-up on all privileged machine identities",
        "Enable zero-trust continuous verification for admin scopes",
    ],
    "ai_prompt_injection": [
        "Tighten prohibited-pattern list in the AI policy engine",
        "Route all AI calls through the real-time enforcer",
        "Add human review for interactions scoring >50",
    ],
    "data_exfiltration": [
        "Remediate critical code findings this sprint",
        "Add egress monitoring on data stores",
    ],
    "ransomware": [
        "Verify offline backups and restore drills",
        "Patch internet-facing services flagged in KEV",
    ],
    "invoice_fraud": [
        "Enable dual-approval for new beneficiaries",
        "Turn on IBAN-change detection alerts",
    ],
}


def forecast(org_id: str) -> dict:
    trend = score_model.trend_analysis(org_id)
    landscape = trend_analyzer.current_threat_landscape()
    horizons = {}
    for h in _HORIZONS:
        p = predictor.predict_incidents(org_id, horizon_days=h)
        horizons[f"{h}d"] = {
            "headline": p["headline"],
            "top_risks": p["predictions"][:3],
        }

    top_vector = horizons["30d"]["top_risks"][0]["vector"] if horizons["30d"]["top_risks"] else None
    recommendations = _PLAYBOOKS.get(top_vector, ["Maintain current controls; review posture monthly"])

    return {
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "posture_trend": trend["prediction"],
        "threat_landscape": landscape,
        "horizons": horizons,
        "proactive_recommendations": recommendations,
    }
