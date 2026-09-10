"""Health checks and the Chakra internal health-score endpoint."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, text

from core.api.middleware.auth import require_internal_secret
from core.database.db import engine, session_scope
from core.database.models import Organisation
from core.services.unified_risk_score import score_calculator
from core.utils.config import settings

router = APIRouter()
internal_router = APIRouter()


@router.get("/health")
def health() -> dict:
    checks = {"api": "ok"}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {exc}"
    try:
        import redis  # type: ignore

        redis.from_url(settings.REDIS_URL, socket_connect_timeout=1).ping()
        checks["redis"] = "ok"
    except Exception:  # noqa: BLE001
        checks["redis"] = "unavailable"

    healthy = checks["database"] == "ok"
    return {
        "status": "healthy" if healthy else "degraded",
        "version": settings.VERSION,
        "time": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


@internal_router.get("/health-score")
def chakra_health_score(
    chakra_org_id: str = Query(...),
    _: None = Depends(require_internal_secret),
) -> dict:
    """Return the security score to Chakra Intelligence."""
    with session_scope() as db:
        org = db.scalar(
            select(Organisation).where(Organisation.chakra_org_id == chakra_org_id)
        ) or db.scalar(select(Organisation))
        if not org:
            return {"chakra_org_id": chakra_org_id, "security_score": None, "error": "no org"}
        org_id = org.id

    result = score_calculator.calculate(org_id)
    return {
        "chakra_org_id": chakra_org_id,
        "security_score": result["overall"],
        "grade": result["grade"],
        "breakdown": result["breakdown"],
        "generated_at": result["timestamp"],
    }
