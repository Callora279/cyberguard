"""Live Scan API: register authorised targets, run live scans."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from core.api.middleware.auth import Principal, get_principal
from core.services.livescan import scanner
from core.services.livescan.authorization import NotAuthorizedError, register_target  # noqa: F401

router = APIRouter()


class RegisterTargetIn(BaseModel):
    target_url: str


class ScanTargetIn(BaseModel):
    target_url: str


@router.post("/targets")
def register(body: RegisterTargetIn, principal: Principal = Depends(get_principal)) -> dict:
    # ValidationError / NotAuthorizedError propagate to the app's exception handlers.
    return register_target(principal.org_id, body.target_url, attested_by=principal.org_id)


@router.post("/scan")
async def scan(body: ScanTargetIn, principal: Principal = Depends(get_principal)) -> dict:
    # NotAuthorizedError propagates to the global handler for the correct status.
    result = await scanner.scan_target(principal.org_id, body.target_url)
    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "reachable": result.reachable,
        "fingerprint": result.fingerprint,
        "counts": result.counts,
        "findings": result.findings,
        "decision": result.decision.decision if result.decision else None,
    }
