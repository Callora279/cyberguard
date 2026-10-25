"""Security Debt API: scan, heatmap, remediation queue."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal
from core.database.db import session_scope
from core.database.models import SecurityFinding
from core.database.org_repo import connected_repo
from core.services.security_debt import remediation_assistant, reporting
from core.services.security_debt.heatmap_engine import heatmap_builder, heatmap_visualizer
from core.utils.exceptions import NotFoundError, ValidationError

router = APIRouter()


class ScanIn(BaseModel):
    path: str | None = None
    repo_url: str | None = None
    github_token: str | None = None
    include_dependencies: bool = True


class JiraIn(BaseModel):
    finding_id: str | None = None  # one finding; omit to file the top open findings


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
    repo_url, token = body.repo_url, body.github_token
    if not repo_url and not body.path:
        # No explicit target: use the org's connected repo. Never fall back to
        # scanning this server's own source tree for an org-scoped scan.
        repo_url, token = connected_repo(principal.org_id)
        if not repo_url:
            raise ValidationError(
                "no path or repo_url given, and this org has no connected repo configured"
            )
    if repo_url:
        return reporting.run_scan_github(
            principal.org_id, repo_url, token=token, include_dependencies=body.include_dependencies
        )
    path = body.path
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
def create_jira(body: JiraIn | None = None, principal: Principal = Depends(get_principal)) -> dict:
    if body and body.finding_id:
        from agents.jira.jira_agent import JiraAgent

        agent = JiraAgent(principal.org_id)
        return {"created": [agent.create_ticket_for_finding(body.finding_id, principal.org_id)]}
    findings = sorted(_open_findings(principal.org_id), key=lambda f: f["priority_score"], reverse=True)[:10]
    return {"created": remediation_assistant.create_jira_tickets(findings, org_id=principal.org_id)}


@router.post("/remediation/jira/sync")
def sync_jira(principal: Principal = Depends(get_principal)) -> dict:
    from agents.jira.jira_agent import JiraAgent

    agent = JiraAgent(principal.org_id)
    return {
        "pulled": agent.sync_remediation_progress(principal.org_id),
        "closed": agent.close_resolved_tickets(principal.org_id),
        "sla": agent.sla_report(principal.org_id),
    }
