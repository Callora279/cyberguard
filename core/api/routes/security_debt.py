"""Security Debt API: scan, heatmap, remediation queue."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal
from core.database.db import session_scope
from core.database.models import SecurityFinding
from core.services.security_debt import remediation_assistant, reporting
from core.services.security_debt.heatmap_engine import heatmap_builder, heatmap_visualizer
from core.utils.exceptions import NotFoundError, ValidationError

router = APIRouter()
_DEFAULT_PATH = os.getenv("SCAN_TARGET_PATH", ".")


class ScanIn(BaseModel):
    path: str | None = None
    repo_url: str | None = None
    github_token: str | None = None
    include_dependencies: bool = True


def _open_findings(org_id: str) -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(
            select(SecurityFinding).where(
                SecurityFinding.org_id == org_id, SecurityFinding.status == "open"
            )
        ).all()
        return [
            {
                "id": r.id, "type": r.type, "title": r.title, "severity": r.severity,
                "file_path": r.file_path, "line": r.line, "status": r.status,
                "priority_score": r.priority_score,
            }
            for r in rows
        ]


@router.get("/scan")
def get_scan(principal: Principal = Depends(get_principal)) -> dict:
    return reporting.summary(principal.org_id)


@router.post("/scan")
def run_scan(body: ScanIn, principal: Principal = Depends(get_principal)) -> dict:
    if body.repo_url:
        return reporting.run_scan_github(
            principal.org_id,
            body.repo_url,
            token=body.github_token,
            include_dependencies=body.include_dependencies,
        )
    path = body.path or _DEFAULT_PATH
    if not os.path.isdir(path):
        raise ValidationError(f"path not found: {path}")
    return reporting.run_scan(principal.org_id, path, include_dependencies=body.include_dependencies)


@router.get("/heatmap")
def heatmap(fmt: str = "json", principal: Principal = Depends(get_principal)) -> dict:
    hm = heatmap_builder.build(_open_findings(principal.org_id))
    if fmt == "html":
        return {"format": "html", "content": heatmap_visualizer.to_html(hm)}
    if fmt == "ascii":
        return {"format": "ascii", "content": heatmap_visualizer.to_ascii(hm)}
    return hm


@router.get("/remediation")
def remediation(principal: Principal = Depends(get_principal), use_ai: bool = True) -> dict:
    findings = sorted(_open_findings(principal.org_id), key=lambda f: f["priority_score"], reverse=True)
    top = findings[:10]
    return {
        "queue": [
            remediation_assistant.suggest(f, org_id=principal.org_id, use_ai=use_ai)
            for f in top
        ],
        "total_open": len(findings),
    }


@router.post("/remediation/jira")
def create_jira(principal: Principal = Depends(get_principal)) -> dict:
    findings = sorted(_open_findings(principal.org_id), key=lambda f: f["priority_score"], reverse=True)[:10]
    return {"created": remediation_assistant.create_jira_tickets(findings, org_id=principal.org_id)}
