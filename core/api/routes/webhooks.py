"""Inbound SCM webhooks: GitHub & GitLab push / PR events.

These endpoints are unauthenticated (called by GitHub/GitLab) so every request
is verified against the per-org webhook secret stored in ``org_settings`` (or
the global ``GITHUB_WEBHOOK_SECRET`` / ``GITLAB_WEBHOOK_TOKEN`` fallback) before
anything runs. The org is resolved from an ``?org_id=`` query param or by
matching the payload's repository URL against a connected repo.

Push and pull/merge-request events enqueue the continuous security gate
(``run_gate_for_event``) and return 202 immediately; nothing is scanned in the
request. Other events are acknowledged with 204.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import OrgSettings
from core.utils.config import settings
from core.utils.exceptions import AuthError, NotFoundError, ValidationError
from core.utils.logger import get_logger
from core.utils.webhook_verify import verify_github, verify_gitlab

router = APIRouter()
logger = get_logger("api.webhooks")

_GITHUB_PR_ACTIONS = {"opened", "synchronize", "reopened"}
_GITLAB_MR_ACTIONS = {"open", "update", "reopen"}


def _resolve_org(org_id: str | None, repo_url: str | None) -> OrgSettings:
    with session_scope() as db:
        if org_id:
            row = db.get(OrgSettings, org_id)
            if row:
                db.expunge(row)
                return row
        if repo_url:
            needle = repo_url.rstrip("/").removesuffix(".git").lower()
            rows = db.scalars(
                select(OrgSettings).where(OrgSettings.github_repo_url.is_not(None))
            ).all()
            for r in rows:
                if (r.github_repo_url or "").rstrip("/").removesuffix(".git").lower() == needle:
                    db.expunge(r)
                    return r
    raise NotFoundError("no organisation is connected to this repository")


def _find_org(org_id: str | None, repo_url: str | None) -> OrgSettings | None:
    try:
        return _resolve_org(org_id, repo_url)
    except NotFoundError:
        return None


def _parse_json(body: bytes) -> dict | None:
    if not body:
        return {}
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _branch(ref: str) -> str | None:
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix):]
    return None


def _deleted_sha(sha: str | None) -> bool:
    return not sha or not sha.strip("0")


def _github_gate_event(event: str, payload: dict, org_id: str | None) -> dict | None:
    repo = (payload.get("repository") or {}).get("full_name")
    if not repo:
        return None
    if event == "push":
        ref = _branch(payload.get("ref") or "")
        sha = payload.get("after")
        if not ref or payload.get("deleted") or _deleted_sha(sha):
            return None
        return {"provider": "github", "event": "push", "org_id": org_id, "repo": repo,
                "clone_repo": repo, "ref": ref, "commit_sha": sha}
    if event == "pull_request" and payload.get("action") in _GITHUB_PR_ACTIONS:
        head = (payload.get("pull_request") or {}).get("head") or {}
        if not head.get("ref") or not head.get("sha"):
            return None
        return {"provider": "github", "event": "pull_request", "org_id": org_id, "repo": repo,
                # fork PRs: clone the head repo, report status on the base repo
                "clone_repo": (head.get("repo") or {}).get("full_name") or repo,
                "ref": head["ref"], "commit_sha": head["sha"]}
    return None


def _gitlab_gate_event(event: str, payload: dict, org_id: str | None) -> dict | None:
    project = payload.get("project") or {}
    path = project.get("path_with_namespace")
    if not path:
        return None
    if event == "Push Hook":
        ref = _branch(payload.get("ref") or "")
        sha = payload.get("checkout_sha") or payload.get("after")
        if not ref or _deleted_sha(sha):
            return None
        return {"provider": "gitlab", "event": "push", "org_id": org_id, "repo": path,
                "project_id": project.get("id"), "clone_repo": path, "ref": ref, "commit_sha": sha}
    if event == "Merge Request Hook":
        oa = payload.get("object_attributes") or {}
        if oa.get("action") not in _GITLAB_MR_ACTIONS:
            return None
        if oa.get("action") == "update" and not oa.get("oldrev"):
            return None  # title/label edit, no new commits
        sha = (oa.get("last_commit") or {}).get("id")
        if not oa.get("source_branch") or not sha:
            return None
        return {"provider": "gitlab", "event": "merge_request", "org_id": org_id, "repo": path,
                "project_id": oa.get("source_project_id") or project.get("id"),
                "clone_repo": (oa.get("source") or {}).get("path_with_namespace") or path,
                "ref": oa["source_branch"], "commit_sha": sha}
    return None


def _enqueue_gate(event: dict, background: BackgroundTasks) -> None:
    from core.workers.background_tasks import run_gate_for_event
    from core.workers.queue import celery_app

    if celery_app is not None:
        try:
            run_gate_for_event.delay(event)
            return
        except Exception as exc:  # noqa: BLE001 - broker down: still gate, off the request path
            logger.warning("could not enqueue gate task (%s); running after response", exc)
    background.add_task(run_gate_for_event, event)


def _run_legacy(handler, event: str, payload: dict, org_id: str) -> None:
    """The pre-gate SBOM / PR-comment handling, now run after the response."""
    try:
        handler(event, payload, org_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("legacy %s webhook handling failed for org=%s: %s", event, org_id, exc)


def _accepted(provider: str, event: str, gate_event: dict) -> JSONResponse:
    return JSONResponse(
        status_code=202,
        content={
            "accepted": True,
            "provider": provider,
            "event": event,
            "org_id": gate_event.get("org_id"),
            "repo": gate_event["repo"],
            "commit_sha": gate_event["commit_sha"],
        },
    )


@router.post("/github", status_code=202)
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
    org_id: str | None = Query(default=None),
    x_github_event: str = Header(default="ping"),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()
    payload = _parse_json(body)
    repo = (payload or {}).get("repository") or {}
    settings_row = _find_org(org_id, repo.get("html_url") or repo.get("clone_url"))

    secret = (settings_row.github_webhook_secret if settings_row else None) or settings.GITHUB_WEBHOOK_SECRET
    if not verify_github(body, x_hub_signature_256 or "", secret or ""):
        raise AuthError("invalid or missing webhook signature")
    if payload is None:
        raise ValidationError("webhook body is not a JSON object")

    resolved_org = settings_row.org_id if settings_row else None
    if x_github_event == "ping":
        return JSONResponse({"ok": True, "event": "ping", "org_id": resolved_org})

    gate_event = _github_gate_event(x_github_event, payload, resolved_org)
    if gate_event is None:
        return Response(status_code=204)

    _enqueue_gate(gate_event, background)
    if resolved_org:
        from agents.github.github_agent import handle_webhook

        background.add_task(_run_legacy, handle_webhook, x_github_event, payload, resolved_org)
    logger.info("github %s for %s@%s queued for gate (org=%s)",
                x_github_event, gate_event["repo"], gate_event["commit_sha"], resolved_org)
    return _accepted("github", x_github_event, gate_event)


@router.post("/gitlab", status_code=202)
async def gitlab_webhook(
    request: Request,
    background: BackgroundTasks,
    org_id: str | None = Query(default=None),
    x_gitlab_event: str = Header(default="Push Hook"),
    x_gitlab_token: str | None = Header(default=None),
):
    body = await request.body()
    payload = _parse_json(body)
    project = (payload or {}).get("project") or {}
    settings_row = _find_org(
        org_id, project.get("web_url") or ((payload or {}).get("repository") or {}).get("homepage")
    )

    # shared secret column for both SCMs, then the global GitLab token
    secret = (settings_row.github_webhook_secret if settings_row else None) or settings.GITLAB_WEBHOOK_TOKEN
    if not verify_gitlab(x_gitlab_token or "", secret or ""):
        raise AuthError("invalid or missing X-Gitlab-Token")
    if payload is None:
        raise ValidationError("webhook body is not a JSON object")

    resolved_org = settings_row.org_id if settings_row else None
    gate_event = _gitlab_gate_event(x_gitlab_event, payload, resolved_org)
    if gate_event is None:
        return Response(status_code=204)

    _enqueue_gate(gate_event, background)
    if resolved_org:
        from agents.gitlab.gitlab_agent import handle_webhook

        background.add_task(_run_legacy, handle_webhook, x_gitlab_event, payload, resolved_org)
    logger.info("gitlab %s for %s@%s queued for gate (org=%s)",
                x_gitlab_event, gate_event["repo"], gate_event["commit_sha"], resolved_org)
    return _accepted("gitlab", x_gitlab_event, gate_event)
