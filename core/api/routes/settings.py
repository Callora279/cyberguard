"""Organisation settings: integrations, notifications, CLI tokens, billing."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal, require_admin
from core.database.db import session_scope
from core.database.models import ApiToken, Organisation
from core.services import onboarding
from core.utils.crypto import new_secret, sha256_hex
from core.utils.exceptions import NotFoundError

router = APIRouter()

_PLAN_LIMITS = {
    "trial": {"repos": 3, "websites": 3, "team_members": 5, "scans_per_day": 25},
    "free": {"repos": 1, "websites": 1, "team_members": 2, "scans_per_day": 10},
    "pro": {"repos": 25, "websites": 25, "team_members": 25, "scans_per_day": 500},
    "enterprise": {"repos": -1, "websites": -1, "team_members": -1, "scans_per_day": -1},
}


class SettingsPatch(BaseModel):
    github_repo_url: str | None = None
    github_token: str | None = None
    website_url: str | None = None
    slack_webhook_url: str | None = None
    report_email: EmailStr | None = None
    alert_threshold: str | None = None


class TokenIn(BaseModel):
    name: str = "CLI token"


@router.get("")
def get_settings(principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.get_or_create_settings(principal.org_id)


@router.put("")
def update_settings(body: SettingsPatch, principal: Principal = Depends(require_admin)) -> dict:
    patch = body.model_dump(exclude_none=True)
    if "report_email" in patch:
        patch["report_email"] = str(patch["report_email"])
    return onboarding.update_settings(principal.org_id, patch)


@router.get("/billing")
def billing(principal: Principal = Depends(get_principal)) -> dict:
    with session_scope() as db:
        org = db.get(Organisation, principal.org_id)
        if not org:
            raise NotFoundError("organisation")
        ends = org.trial_ends_at
        if ends and ends.tzinfo is None:
            ends = ends.replace(tzinfo=timezone.utc)
        days_left = None
        if ends:
            days_left = max(0, (ends - datetime.now(timezone.utc)).days)
        return {
            "plan": org.plan,
            "license_key": bool(org.license_key),
            "trial_ends_at": org.trial_ends_at,
            "trial_days_left": days_left,
            "limits": _PLAN_LIMITS.get(org.plan, _PLAN_LIMITS["trial"]),
        }


# ---- CLI / CI access tokens -------------------------------------------------
@router.get("/api-tokens")
def list_tokens(principal: Principal = Depends(get_principal)) -> dict:
    with session_scope() as db:
        rows = db.scalars(
            select(ApiToken)
            .where(ApiToken.org_id == principal.org_id, ApiToken.revoked.is_(False))
            .order_by(ApiToken.created_at.desc())
        ).all()
        return {
            "tokens": [
                {
                    "id": t.id, "name": t.name, "prefix": t.prefix,
                    "created_at": t.created_at, "last_used_at": t.last_used_at,
                }
                for t in rows
            ]
        }


@router.post("/api-tokens")
def create_token(body: TokenIn, principal: Principal = Depends(require_admin)) -> dict:
    raw = new_secret("cgcli")
    prefix = raw[:12]
    with session_scope() as db:
        token = ApiToken(
            org_id=principal.org_id,
            created_by=principal.user_id,
            name=body.name,
            prefix=prefix,
            token_hash=sha256_hex(raw),
        )
        db.add(token)
        db.flush()
        tid = token.id
    # full token shown once
    return {"id": tid, "name": body.name, "token": raw,
            "note": "Store this now — it will not be shown again."}


@router.delete("/api-tokens/{token_id}")
def revoke_token(token_id: str, principal: Principal = Depends(require_admin)) -> dict:
    with session_scope() as db:
        t = db.get(ApiToken, token_id)
        if not t or t.org_id != principal.org_id:
            raise NotFoundError("token")
        t.revoked = True
        return {"id": token_id, "revoked": True}
