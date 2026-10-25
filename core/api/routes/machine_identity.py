"""Machine Identity API: registry, register, rotate, alerts, zero-trust."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal
from core.database.db import session_scope
from core.database.models import Alert
from core.services.machine_identity import (
    behaviour_monitor,
    credential_rotation,
    identity_registry,
    zero_trust,
)
from core.services.machine_identity.identity_dna import dna_analyzer, dna_generator

router = APIRouter()


class RegisterIn(BaseModel):
    identity_type: str
    name: str
    owner: str = ""
    scopes: list[str] = []
    secret_material: str | None = None
    expires_at: datetime | None = None


class RotateIn(BaseModel):
    identity_id: str
    grace_period_hours: int = 24
    dry_run: bool = False


class AccessIn(BaseModel):
    identity_id: str
    resource: str
    action: str = "read"
    ip: str = ""
    geo: str = ""
    device_managed: bool = False
    mfa_present: bool = False
    auth_age_seconds: int = 0


@router.get("/registry")
def registry(identity_type: str | None = None, principal: Principal = Depends(get_principal)) -> dict:
    items = identity_registry.list_registry(principal.org_id, identity_type=identity_type)
    return {"count": len(items), "identities": items}


@router.post("/register")
def register(body: RegisterIn, principal: Principal = Depends(get_principal)) -> dict:
    return identity_registry.register(
        principal.org_id,
        identity_type=body.identity_type,
        name=body.name,
        owner=body.owner,
        scopes=body.scopes,
        secret_material=body.secret_material,
        expires_at=body.expires_at,
    )


@router.post("/rotate")
def rotate(body: RotateIn, principal: Principal = Depends(get_principal)) -> dict:
    result = credential_rotation.rotate(
        body.identity_id, grace_period_hours=body.grace_period_hours, dry_run=body.dry_run
    )
    return result


@router.post("/rotate-due")
def rotate_due(principal: Principal = Depends(get_principal)) -> dict:
    identity_registry.check_expiries(principal.org_id)
    return credential_rotation.rotate_due(principal.org_id)


@router.get("/alerts")
def alerts(principal: Principal = Depends(get_principal)) -> dict:
    expiry = identity_registry.check_expiries(principal.org_id)
    expiring_soon = credential_rotation.notify_expiring(principal.org_id, within_days=30)
    stale = behaviour_monitor.check_stale(principal.org_id, days=30)
    with session_scope() as db:
        rows = db.scalars(
            select(Alert)
            .where(Alert.org_id == principal.org_id, Alert.module == "machine_identity")
            .order_by(Alert.created_at.desc())
            .limit(50)
        ).all()
        feed = [
            {"id": a.id, "severity": a.severity, "title": a.title, "body": a.body, "created_at": a.created_at}
            for a in rows
        ]
    return {
        "expiry_sweep": expiry,
        "expiring_within_30d": expiring_soon["expiring"],
        "stale_credentials": stale["stale"],
        "alerts": feed,
    }


@router.get("/history")
def history(identity_id: str | None = None, principal: Principal = Depends(get_principal)) -> dict:
    return {"rotations": credential_rotation.history(identity_id)}


@router.post("/access-request")
def access_request(body: AccessIn, principal: Principal = Depends(get_principal)) -> dict:
    result = zero_trust.request_access(
        zero_trust.AccessRequest(org_id=principal.org_id, **body.model_dump())
    )
    dna_generator.record_event(body.identity_id, endpoint=body.resource, ip=body.ip)
    return result


@router.get("/{identity_id}/dna")
def identity_dna(identity_id: str, principal: Principal = Depends(get_principal)) -> dict:
    return {
        "analysis": dna_analyzer.analyze(identity_id),
        "behaviour": behaviour_monitor.profile_summary(identity_id),
    }


class FingerprintCheckIn(BaseModel):
    hour: int | None = None
    endpoint: str | None = None
    ip: str | None = None
    requests_last_hour: int | None = None


@router.get("/{identity_id}/fingerprint")
def fingerprint(identity_id: str, days: int = 7, principal: Principal = Depends(get_principal)) -> dict:
    """The behavioural fingerprint built from the last ``days`` of access
    events: normal hours, normal endpoints, average hourly rate, normal IPs."""
    return dna_generator.generate_fingerprint(identity_id, days=days)


@router.post("/{identity_id}/fingerprint/check")
def fingerprint_check(
    identity_id: str, body: FingerprintCheckIn, principal: Principal = Depends(get_principal)
) -> dict:
    """Compare a live access event against the stored fingerprint and score
    the deviation (off-hours, new endpoint, rate spike, new IP)."""
    return dna_analyzer.analyze_fingerprint(identity_id, live_event=body.model_dump(exclude_none=True))
