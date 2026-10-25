"""Organisation settings: integrations, notifications, CLI tokens, billing."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal, require_admin
from core.database.db import session_scope
from core.database.models import ApiToken, Organisation
from core.services import ai_client, onboarding
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
    github_webhook_secret: str | None = None
    website_url: str | None = None
    slack_webhook_url: str | None = None
    slack_daily_digest: bool | None = None
    report_email: EmailStr | None = None
    alert_threshold: str | None = None
    notification_email: EmailStr | None = None
    notify_types: list[str] | None = None
    weekly_digest: bool | None = None
    jira_url: str | None = None
    jira_user: str | None = None
    jira_token: str | None = None
    jira_project_key: str | None = None


class AISettingsPatch(BaseModel):
    provider: str
    model: str
    api_key: str | None = None  # blank/omitted = keep the existing key
    base_url: str | None = None  # custom/self-hosted only
    max_tokens: int = 1024
    temperature: float = 0.2


class TokenIn(BaseModel):
    name: str = "CLI token"


class TestIn(BaseModel):
    integration: str  # slack | email | jira | github


@router.get("")
def get_settings(principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.get_or_create_settings(principal.org_id)


@router.put("")
def update_settings(body: SettingsPatch, principal: Principal = Depends(require_admin)) -> dict:
    patch = body.model_dump(exclude_none=True)
    for key in ("report_email", "notification_email"):
        if key in patch:
            patch[key] = str(patch[key])
    return onboarding.update_settings(principal.org_id, patch)


@router.get("/ai/providers")
def ai_providers() -> dict:
    """Static catalogue for the Settings page's provider/model dropdowns."""
    return {"providers": ai_client.PROVIDER_CATALOG}


@router.get("/ai")
def get_ai_settings(principal: Principal = Depends(get_principal)) -> dict:
    return ai_client.describe_org_settings(principal.org_id)


@router.put("/ai")
def update_ai_settings(body: AISettingsPatch, principal: Principal = Depends(require_admin)) -> dict:
    return ai_client.save_org_settings(
        principal.org_id,
        provider=body.provider,
        model=body.model,
        api_key=body.api_key,
        base_url=body.base_url,
        max_tokens=body.max_tokens,
        temperature=body.temperature,
    )


@router.post("/ai/test")
def test_ai_connection(principal: Principal = Depends(require_admin)) -> dict:
    return ai_client.test_connection(principal.org_id)


@router.post("/integrations/test")
def test_integration(body: TestIn, principal: Principal = Depends(require_admin)) -> dict:
    """Fire a real test message / connection check for one integration."""
    from core.database.models import OrgSettings

    with session_scope() as db:
        row = db.get(OrgSettings, principal.org_id)
        cfg = {
            "slack_webhook_url": row.slack_webhook_url if row else None,
            "notification_email": (row.notification_email or row.report_email) if row else None,
            "jira_url": row.jira_url if row else None,
            "github_repo_url": row.github_repo_url if row else None,
            "github_token": row.github_token if row else None,
        }

    kind = body.integration
    if kind == "slack":
        from core.services.notifications import slack_service

        r = slack_service.send_text(
            cfg["slack_webhook_url"], ":white_check_mark: CyberGuard AI test message — Slack is connected."
        )
        return {"integration": "slack", "ok": r.get("sent", False), "detail": r}

    if kind == "email":
        from core.services.notifications import email_service

        r = email_service.send(
            cfg["notification_email"],
            "CyberGuard AI — test email",
            html="<p>This is a test email. Notifications are configured correctly.</p>",
            text="This is a test email. Notifications are configured correctly.",
        )
        return {"integration": "email", "ok": r.get("sent", False), "detail": r}

    if kind == "jira":
        from agents.jira.jira_agent import JiraAgent

        agent = JiraAgent(principal.org_id)
        if not agent.enabled:
            return {"integration": "jira", "ok": False, "detail": "Jira not configured"}
        import httpx

        try:
            resp = httpx.get(f"{agent.base}/rest/api/2/myself", auth=agent.auth, timeout=10.0)
            return {"integration": "jira", "ok": resp.status_code == 200,
                    "detail": {"status": resp.status_code}}
        except httpx.HTTPError as exc:
            return {"integration": "jira", "ok": False, "detail": str(exc)}

    if kind == "github":
        if not cfg["github_repo_url"]:
            return {"integration": "github", "ok": False, "detail": "no repo configured"}
        import httpx

        from core.utils.github import parse_repo_url

        try:
            repo = parse_repo_url(cfg["github_repo_url"])
            headers = {"Accept": "application/vnd.github+json"}
            if cfg["github_token"]:
                headers["Authorization"] = f"Bearer {cfg['github_token']}"
            resp = httpx.get(f"https://api.github.com/repos/{repo}", headers=headers, timeout=10.0)
            return {"integration": "github", "ok": resp.status_code == 200,
                    "detail": {"status": resp.status_code, "repo": repo}}
        except (httpx.HTTPError, Exception) as exc:  # noqa: BLE001
            return {"integration": "github", "ok": False, "detail": str(exc)}

    return {"integration": kind, "ok": False, "detail": "unknown integration"}


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
