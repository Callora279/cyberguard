"""Client onboarding wizard API."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field

from core.api.middleware.auth import Principal, get_principal
from core.services import onboarding

router = APIRouter()


class GitHubIn(BaseModel):
    repo_url: str
    token: str | None = None


class WebsiteIn(BaseModel):
    url: str
    threshold: str = "medium"


class AlertsIn(BaseModel):
    slack_webhook_url: str | None = None
    report_email: EmailStr | None = None
    alert_threshold: str = Field(default="high", pattern="^(critical|high|medium|low)$")


class SkipIn(BaseModel):
    step: int = Field(ge=1, le=4)


@router.get("/status")
def get_status(principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.status(principal.org_id)


@router.post("/github")
def connect_github(body: GitHubIn, principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.connect_github(
        principal.org_id, repo_url=body.repo_url, token=body.token
    )


@router.post("/website")
def scan_website(body: WebsiteIn, principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.scan_website(
        principal.org_id, url=body.url, threshold=body.threshold
    )


@router.post("/alerts")
def save_alerts(body: AlertsIn, principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.save_alert_config(
        principal.org_id,
        slack_webhook_url=body.slack_webhook_url,
        report_email=str(body.report_email) if body.report_email else None,
        alert_threshold=body.alert_threshold,
    )


@router.post("/skip")
def skip(body: SkipIn, principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.skip_step(principal.org_id, body.step)


@router.post("/complete")
def complete(principal: Principal = Depends(get_principal)) -> dict:
    return onboarding.complete(principal.org_id)
