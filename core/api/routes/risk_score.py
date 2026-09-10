"""Unified risk score + predictive risk API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from core.api.middleware.auth import Principal, get_principal
from core.services.predictive_risk import predictor, risk_forecast, trend_analyzer
from core.services.unified_risk_score import (
    score_calculator,
    score_dashboard,
    score_insight,
    score_model,
)

router = APIRouter()


@router.get("/current")
def current(
    recalculate: bool = True,
    insight: bool = False,
    principal: Principal = Depends(get_principal),
) -> dict:
    result = (
        score_calculator.calculate(principal.org_id)
        if recalculate
        else score_dashboard.build(principal.org_id, recalculate=False)
    )
    if insight:
        result["insight"] = score_insight.generate(result, org_id=principal.org_id)
    return result


@router.get("/insight")
def insight(principal: Principal = Depends(get_principal)) -> dict:
    result = score_calculator.calculate(principal.org_id)
    return {
        "overall": result["overall"],
        "grade": result["grade"],
        "insight": score_insight.generate(result, org_id=principal.org_id),
    }


@router.get("/dashboard")
def dashboard(principal: Principal = Depends(get_principal)) -> dict:
    return score_dashboard.build(principal.org_id)


@router.get("/history")
def history(days: int = Query(30, le=365), principal: Principal = Depends(get_principal)) -> dict:
    return {
        "series": score_dashboard.history_series(principal.org_id, days=days),
        "trend": score_model.trend_analysis(principal.org_id),
    }


@router.get("/forecast")
def forecast(horizon_days: int = Query(30, ge=1, le=180), principal: Principal = Depends(get_principal)) -> dict:
    return {
        "incident_forecast": predictor.predict_incidents(principal.org_id, horizon_days=horizon_days),
        "multi_horizon": risk_forecast.forecast(principal.org_id),
        "internal_trends": trend_analyzer.internal_trends(principal.org_id),
    }
