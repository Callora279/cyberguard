"""Predict future security incidents from current posture + threat intel."""
from __future__ import annotations

from datetime import datetime, timezone

from core.services.supply_chain import alerts as sc_alerts
from core.services.security_debt import reporting as debt_reporting
from core.services.unified_risk_score import score_model
from core.services.predictive_risk import trend_analyzer

# base annual incident probabilities by vector (industry priors)
_BASE_RATES = {
    "supply_chain_attack": 0.18,
    "credential_compromise": 0.22,
    "ai_prompt_injection": 0.15,
    "data_exfiltration": 0.12,
    "ransomware": 0.10,
    "invoice_fraud": 0.14,
}


def _logistic(x: float) -> float:
    import math

    return 1 / (1 + math.exp(-x))


def predict_incidents(org_id: str, *, horizon_days: int = 30) -> dict:
    debt = debt_reporting.summary(org_id)
    components = sc_alerts.list_components(org_id)
    trend = score_model.predict(org_id)
    threat = trend_analyzer.current_threat_landscape()

    crit_debt = debt["by_severity"].get("critical", 0) + debt["by_severity"].get("high", 0)
    vuln_deps = sum(1 for c in components if c["cve_count"] > 0)
    declining = trend.get("direction") == "declining"

    horizon_factor = horizon_days / 365.0
    predictions = []
    for vector, base in _BASE_RATES.items():
        modifier = 0.0
        if vector == "supply_chain_attack":
            modifier += min(1.5, vuln_deps * 0.15)
        if vector == "credential_compromise":
            modifier += 0.4 if declining else 0.0
        if vector == "ai_prompt_injection":
            modifier += threat.get("ai_attack_momentum", 0.0)
        if vector in ("data_exfiltration", "ransomware"):
            modifier += min(1.2, crit_debt * 0.2)
        if vector == "invoice_fraud":
            modifier += threat.get("fraud_momentum", 0.0)
        if declining:
            modifier += 0.25

        prob = _logistic(_odds(base) + modifier) * (0.4 + horizon_factor)
        prob = round(min(0.95, prob), 3)
        predictions.append(
            {
                "vector": vector,
                "probability": prob,
                "severity_if_realised": "high" if prob > 0.4 else "medium",
                "drivers": _drivers(vector, vuln_deps, crit_debt, declining),
            }
        )

    predictions.sort(key=lambda p: p["probability"], reverse=True)
    return {
        "org_id": org_id,
        "horizon_days": horizon_days,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "predictions": predictions,
        "headline": _headline(predictions[0], horizon_days),
        "threat_landscape": threat,
    }


def _odds(p: float) -> float:
    import math

    p = min(0.999, max(0.001, p))
    return math.log(p / (1 - p))


def _drivers(vector: str, vuln_deps: int, crit_debt: int, declining: bool) -> list[str]:
    d = []
    if vector == "supply_chain_attack" and vuln_deps:
        d.append(f"{vuln_deps} dependencies with known CVEs")
    if vector in ("data_exfiltration", "ransomware") and crit_debt:
        d.append(f"{crit_debt} critical/high code findings")
    if declining:
        d.append("security posture trending down")
    return d or ["baseline industry rate"]


def _headline(top: dict, horizon: int) -> str:
    pct = int(top["probability"] * 100)
    return (
        f"{pct}% probability of {top['vector'].replace('_', ' ')} "
        f"in the next {horizon} days"
    )
