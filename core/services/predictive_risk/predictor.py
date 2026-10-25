"""Predict future security incidents from current posture + threat intel."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from core.database.db import session_scope
from core.database.models import RiskPrediction
from core.services import ai_client
from core.services.supply_chain import alerts as sc_alerts
from core.services.security_debt import reporting as debt_reporting
from core.services.unified_risk_score import score_model
from core.services.predictive_risk import trend_analyzer
from core.utils.logger import get_logger

logger = get_logger("predictive_risk.predictor")

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


# ---------------------------------------------------------------------------
# Real AI-model prediction (Phase 3): send current posture to the org's
# configured AI provider (or the system default Groq), ask it to reason about
# the top-3 risks, and persist the result. Falls back to the heuristic engine
# above — never lets a forecast page fail just because the model is
# unreachable or misconfigured.
# ---------------------------------------------------------------------------
def gather_current_findings(org_id: str) -> dict:
    """Pull a compact snapshot of every module's current posture — this is
    the ``{current_findings}`` payload sent to the AI model."""
    debt = debt_reporting.summary(org_id)
    components = sc_alerts.list_components(org_id)
    trend = score_model.trend_analysis(org_id)
    prediction = trend.get("prediction", {})
    points = trend.get("points") or []
    return {
        "current_risk_score": points[-1]["score"] if points else prediction.get("current"),
        "risk_score_direction": prediction.get("direction", "unknown"),
        "security_debt": {
            "total_open_findings": debt.get("total_open", 0),
            "by_severity": debt.get("by_severity", {}),
        },
        "supply_chain": {
            "total_components": len(components),
            "components_with_known_cves": sum(1 for c in components if c.get("cve_count", 0) > 0),
            "highest_cvss": max((c.get("max_cvss", 0) for c in components), default=0),
        },
        "recent_anomaly": trend.get("anomaly", {}),
    }


def _normalise_ai_risks(raw: list) -> list[dict]:
    """Coerce the model's JSON into a consistent shape, tolerating minor key
    naming drift (models don't always echo the schema exactly)."""
    out = []
    for item in raw[:3]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("risk_name") or item.get("risk") or "Unnamed risk")
        prob_raw = item.get("probability", item.get("probability_percent", 0))
        try:
            prob = float(str(prob_raw).rstrip("%"))
        except (TypeError, ValueError):
            prob = 0.0
        out.append(
            {
                "name": name,
                "probability": round(max(0.0, min(100.0, prob)), 1),
                "impact": str(item.get("impact") or item.get("impact_if_occurs") or ""),
                "recommended_action": str(item.get("recommended_action") or item.get("action") or ""),
            }
        )
    out.sort(key=lambda r: r["probability"], reverse=True)
    return out


def _heuristic_risks(org_id: str, horizon_days: int) -> list[dict]:
    heuristic = predict_incidents(org_id, horizon_days=horizon_days)
    return [
        {
            "name": p["vector"].replace("_", " ").title(),
            "probability": round(p["probability"] * 100, 1),
            "impact": p["severity_if_realised"],
            "recommended_action": "; ".join(p["drivers"]),
        }
        for p in heuristic["predictions"][:3]
    ]


def _store_predictions(org_id: str, risks: list[dict], *, horizon_days: int, source: str, model: str = "") -> None:
    with session_scope() as db:
        # replace the previous forecast for this org+horizon (each call supersedes the last)
        db.query(RiskPrediction).filter(
            RiskPrediction.org_id == org_id, RiskPrediction.horizon_days == horizon_days
        ).delete()
        for r in risks:
            db.add(
                RiskPrediction(
                    org_id=org_id,
                    horizon_days=horizon_days,
                    risk_name=r["name"],
                    probability=r["probability"],
                    impact=r["impact"],
                    recommended_action=r["recommended_action"],
                    source=source,
                    model=model,
                )
            )


def predict_with_ai(org_id: str, *, horizon_days: int = 30) -> dict:
    """The Phase-3 "real AI model" predictor: sends current findings to the
    org's AI provider and asks for the top-3 risks over ``horizon_days``."""
    findings = gather_current_findings(org_id)
    prompt = (
        "Based on these security findings:\n"
        f"{json.dumps(findings, indent=2, default=str)}\n\n"
        f"Predict the top 3 security risks for this organisation in the next {horizon_days} days. "
        "For each risk provide:\n"
        "- Risk name\n"
        "- Probability (0-100%)\n"
        "- Impact if it occurs\n"
        "- Recommended action\n\n"
        "Respond with ONLY a JSON object of this exact shape (exactly 3 items, "
        "highest probability first): "
        '{"risks": [{"name": "...", "probability": 0-100, "impact": "...", '
        '"recommended_action": "..."}]}'
    )
    model = ""
    provider = None
    try:
        cfg = ai_client.describe_org_settings(org_id)
        record = ai_client.chat_for_org(
            org_id,
            prompt,
            system="You are a senior cybersecurity risk analyst producing a board-ready risk "
            "forecast for a client organisation. Respond with valid JSON only, no commentary.",
            temperature=0.3,
            max_tokens=1024,
            purpose="predictive_risk_forecast",
            json_mode=True,
        )
        try:
            result = json.loads(record.response)
        except json.JSONDecodeError:
            start, end = record.response.find("{"), record.response.rfind("}")
            if not (0 <= start < end):
                raise
            result = json.loads(record.response[start : end + 1])
        risks = _normalise_ai_risks(result.get("risks", []))
        if not risks:
            raise ValueError("model returned no parseable risks")
        source = "ai"
        model = record.model or cfg["model"]
        provider = record.metadata.get("provider", "groq")
    except Exception as exc:  # noqa: BLE001 — a forecast page must never 500 on AI unavailability
        logger.warning("AI risk prediction failed for org=%s (falling back to heuristic): %s", org_id, exc)
        risks = _heuristic_risks(org_id, horizon_days)
        source = "heuristic"

    _store_predictions(org_id, risks, horizon_days=horizon_days, source=source, model=model)
    return {
        "org_id": org_id,
        "horizon_days": horizon_days,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "provider": provider,
        "model": model or None,
        "risks": risks,
    }


def forecast_multi_horizon(org_id: str) -> dict:
    """30 / 60 / 90 day forecast built on top of :func:`predict_with_ai`.

    Only the 30-day horizon calls the AI model directly (a fresh model call
    per horizon would triple the latency/cost of a single dashboard read);
    60/90-day horizons reuse the calibrated heuristic engine, which already
    accepts an arbitrary ``horizon_days``.
    """
    horizons: dict[str, dict] = {"30d": predict_with_ai(org_id, horizon_days=30)}
    for h in (60, 90):
        risks = _heuristic_risks(org_id, h)
        _store_predictions(org_id, risks, horizon_days=h, source="heuristic")
        horizons[f"{h}d"] = {
            "org_id": org_id,
            "horizon_days": h,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "heuristic",
            "risks": risks,
        }
    return {"org_id": org_id, "generated_at": datetime.now(timezone.utc).isoformat(), "horizons": horizons}
