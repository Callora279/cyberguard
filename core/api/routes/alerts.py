"""Unified alert feed across every module."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal
from core.database.db import session_scope
from core.database.models import Alert
from core.utils.exceptions import NotFoundError

router = APIRouter()


@router.get("/alerts")
def list_alerts(
    principal: Principal = Depends(get_principal),
    module: str | None = None,
    severity: str | None = None,
    acknowledged: bool | None = None,
    limit: int = Query(100, le=500),
) -> dict:
    with session_scope() as db:
        stmt = select(Alert).where(Alert.org_id == principal.org_id)
        if module:
            stmt = stmt.where(Alert.module == module)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if acknowledged is not None:
            stmt = stmt.where(Alert.acknowledged.is_(acknowledged))
        rows = db.scalars(stmt.order_by(Alert.created_at.desc()).limit(limit)).all()
        return {
            "count": len(rows),
            "alerts": [
                {
                    "id": a.id, "module": a.module, "severity": a.severity,
                    "title": a.title, "body": a.body, "context": a.context,
                    "acknowledged": a.acknowledged, "created_at": a.created_at,
                }
                for a in rows
            ],
        }


@router.put("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: str, principal: Principal = Depends(get_principal)) -> dict:
    with session_scope() as db:
        a = db.get(Alert, alert_id)
        if not a or a.org_id != principal.org_id:
            raise NotFoundError("alert")
        a.acknowledged = True
        a.acknowledged_by = principal.user_id
        return {
            "id": a.id,
            "acknowledged": True,
            "acknowledged_by": principal.user_id,
            "acknowledged_at": datetime.now(timezone.utc).isoformat(),
        }
