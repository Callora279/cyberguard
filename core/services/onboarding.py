"""Client onboarding: org settings, GitHub connect, website scan, alert config."""
from __future__ import annotations

import tempfile
from pathlib import Path

from sqlalchemy import func, select

from core.database.db import session_scope
from core.database.models import (
    Alert,
    MachineIdentity,
    OrgSettings,
    Organisation,
    SecurityFinding,
)
from core.services.security_debt import reporting as debt_reporting
from core.services.security_debt import website_scanner
from core.services.supply_chain import alerts as sc_alerts
from core.services.supply_chain.ai_generated_sbom import sbom_updater
from core.services.unified_risk_score import score_calculator
from core.utils.exceptions import ValidationError
from core.utils.github import download_repo, parse_repo_url
from core.utils.logger import get_logger
from core.utils.timeutil import utcnow

logger = get_logger("onboarding")

TOTAL_STEPS = 4


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #
def get_or_create_settings(org_id: str) -> dict:
    with session_scope() as db:
        row = db.get(OrgSettings, org_id)
        if not row:
            row = OrgSettings(org_id=org_id)
            db.add(row)
            db.flush()
        return _settings_dict(row)


def update_settings(org_id: str, patch: dict) -> dict:
    allowed = {
        "github_repo_url", "github_token", "website_url",
        "slack_webhook_url", "report_email", "alert_threshold",
    }
    with session_scope() as db:
        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        for key, value in patch.items():
            if key in allowed and value is not None:
                setattr(row, key, value)
        db.flush()
        return _settings_dict(row)


def _mask(value: str | None, keep: int = 4) -> str | None:
    if not value:
        return None
    return "•" * max(0, len(value) - keep) + value[-keep:] if len(value) > keep else "••••"


def _settings_dict(row: OrgSettings, *, reveal: bool = False) -> dict:
    return {
        "org_id": row.org_id,
        "onboarding_completed": row.onboarding_completed,
        "onboarding_step": row.onboarding_step,
        "scan_count": row.scan_count,
        "github": {
            "repo_url": row.github_repo_url,
            "token": row.github_token if reveal else _mask(row.github_token),
            "connected": row.github_connected,
            "last_scan_at": row.github_last_scan_at,
        },
        "website": {
            "url": row.website_url,
            "last_scan_at": row.website_last_scan_at,
            "last_result": row.website_last_result or {},
        },
        "alerts": {
            "slack_webhook_url": row.slack_webhook_url if reveal else _mask(row.slack_webhook_url, 6),
            "report_email": row.report_email,
            "alert_threshold": row.alert_threshold,
        },
        "updated_at": row.updated_at,
    }


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
def status(org_id: str) -> dict:
    settings = get_or_create_settings(org_id)
    with session_scope() as db:
        org = db.get(Organisation, org_id)
        findings = db.scalar(
            select(func.count(SecurityFinding.id)).where(
                SecurityFinding.org_id == org_id, SecurityFinding.status == "open"
            )
        )
        identities = db.scalar(
            select(func.count(MachineIdentity.id)).where(MachineIdentity.org_id == org_id)
        )
        plan = org.plan if org else "trial"
        trial_ends = org.trial_ends_at if org else None

    steps = [
        {"n": 1, "key": "github", "title": "Connect GitHub",
         "done": settings["github"]["connected"]},
        {"n": 2, "key": "website", "title": "Scan your website",
         "done": bool(settings["website"]["url"])},
        {"n": 3, "key": "identities", "title": "Register machine identities",
         "done": (identities or 0) > 0},
        {"n": 4, "key": "alerts", "title": "Set up alerts",
         "done": bool(settings["alerts"]["report_email"] or settings["alerts"]["slack_webhook_url"])},
    ]
    return {
        "completed": settings["onboarding_completed"],
        "current_step": settings["onboarding_step"],
        "total_steps": TOTAL_STEPS,
        "steps": steps,
        "scan_count": settings["scan_count"],
        "open_findings": findings or 0,
        "machine_identities": identities or 0,
        "plan": plan,
        "trial_ends_at": trial_ends,
    }


def _advance(row: OrgSettings, reached_step: int) -> None:
    row.onboarding_step = max(row.onboarding_step, min(reached_step + 1, TOTAL_STEPS))


def skip_step(org_id: str, step: int) -> dict:
    with session_scope() as db:
        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        _advance(row, step)
        db.flush()
    return status(org_id)


def complete(org_id: str) -> dict:
    with session_scope() as db:
        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        row.onboarding_completed = True
        row.onboarding_step = TOTAL_STEPS
    score_calculator.calculate(org_id)  # snapshot the post-onboarding score
    return status(org_id)


# --------------------------------------------------------------------------- #
# step 1 — GitHub
# --------------------------------------------------------------------------- #
def connect_github(org_id: str, *, repo_url: str, token: str | None) -> dict:
    repo = parse_repo_url(repo_url)
    with tempfile.TemporaryDirectory(prefix="cg-onb-") as tmp:
        scan_root = str(download_repo(repo, token, Path(tmp)))

        debt = debt_reporting.run_scan(org_id, scan_root, include_dependencies=True)
        supply = sc_alerts.run_scan(org_id, scan_root)
        try:
            sbom = sbom_updater.update(org_id, scan_root, commit="onboarding")
        except Exception as exc:  # noqa: BLE001
            logger.warning("onboarding SBOM generation failed: %s", exc)
            sbom = {"component_count": 0}

    with session_scope() as db:
        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        row.github_repo_url = repo_url
        row.github_token = token or row.github_token
        row.github_connected = True
        row.github_last_scan_at = utcnow()
        row.scan_count = (row.scan_count or 0) + 1
        _advance(row, 1)

    result = score_calculator.calculate(org_id)
    return {
        "repo": repo,
        "security_debt": debt,
        "supply_chain": supply,
        "sbom_components": sbom.get("component_count", 0),
        "risk_score": result["overall"],
        "status": status(org_id),
    }


# --------------------------------------------------------------------------- #
# step 2 — website
# --------------------------------------------------------------------------- #
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def scan_website(org_id: str, *, url: str, threshold: str = "medium") -> dict:
    report = website_scanner.scan(url)

    min_idx = _SEVERITY_ORDER.index(threshold) if threshold in _SEVERITY_ORDER else 1
    persisted = 0
    with session_scope() as db:
        # replace previous website findings for this org
        db.query(SecurityFinding).filter(
            SecurityFinding.org_id == org_id, SecurityFinding.type == "website"
        ).delete()
        for f in report["findings"]:
            if f["severity"] == "info":
                continue
            db.add(
                SecurityFinding(
                    org_id=org_id,
                    type="website",
                    title=f["title"],
                    file_path=report["origin"],
                    severity=f["severity"],
                    remediation=f.get("detail", ""),
                )
            )
            persisted += 1

        worst = [f for f in report["findings"]
                 if f["severity"] in _SEVERITY_ORDER and _SEVERITY_ORDER.index(f["severity"]) >= min_idx]
        if worst:
            db.add(
                Alert(
                    org_id=org_id,
                    module="security_debt",
                    severity=worst[0]["severity"],
                    title=f"Website scan: {len(worst)} issue(s) at or above '{threshold}'",
                    body="; ".join(f["title"] for f in worst[:5]),
                    context={"url": url, "score": report["score"]},
                )
            )

        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        row.website_url = url
        row.website_last_scan_at = utcnow()
        row.website_last_result = {
            "score": report["score"], "grade": report["grade"],
            "by_severity": report["by_severity"], "checks_run": report["checks_run"],
        }
        row.scan_count = (row.scan_count or 0) + 1
        _advance(row, 2)

    score_calculator.calculate(org_id)
    return {"report": report, "findings_persisted": persisted, "status": status(org_id)}


# --------------------------------------------------------------------------- #
# step 4 — alerts
# --------------------------------------------------------------------------- #
def save_alert_config(
    org_id: str,
    *,
    slack_webhook_url: str | None,
    report_email: str | None,
    alert_threshold: str,
) -> dict:
    if alert_threshold not in _SEVERITY_ORDER + ["critical"]:
        raise ValidationError("alert_threshold must be one of low|medium|high|critical")
    with session_scope() as db:
        row = db.get(OrgSettings, org_id) or OrgSettings(org_id=org_id)
        if not row.org_id:
            row.org_id = org_id
            db.add(row)
        row.slack_webhook_url = slack_webhook_url or row.slack_webhook_url
        row.report_email = report_email or row.report_email
        row.alert_threshold = alert_threshold
        _advance(row, 4)
    return status(org_id)
