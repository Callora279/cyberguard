"""Jira agent: auto-create security tickets, link CVEs, track SLA."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from core.database.db import session_scope
from core.database.models import OrgSettings, SecurityFinding
from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("agents.jira")

# SLA per severity (days to resolve)
_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
_PRIORITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


class JiraAgent:
    def __init__(self, org_id: str | None = None) -> None:
        base, user, token, project = (
            settings.JIRA_URL, settings.JIRA_USER, settings.JIRA_TOKEN, settings.JIRA_PROJECT_KEY
        )
        if org_id:  # per-org config overrides the environment
            with session_scope() as db:
                row = db.get(OrgSettings, org_id)
                if row and row.jira_url:
                    base = row.jira_url
                    user = row.jira_user or user
                    token = row.jira_token or token
                    project = row.jira_project_key or project
        self.org_id = org_id
        self.base = (base or "").rstrip("/")
        self.auth = (user, token) if user and token else None
        self.enabled = bool(self.base and self.auth)
        self.project_key = project or "SEC"

    # ------------------------------------------------------------------ #
    def create_ticket_for_finding(self, finding_id: str, org_id: str | None = None) -> dict:
        """Create a Jira Bug for one security finding and link it back."""
        with session_scope() as db:
            f = db.get(SecurityFinding, finding_id)
            if not f:
                return {"error": "finding not found"}
            severity = f.severity
            summary = f"[CyberGuard] {severity.capitalize()}: {f.title}"
            description = (
                f"Severity: {severity}\n"
                f"Type: {f.type}\n"
                f"Location: {f.file_path}:{f.line}\n"
                f"Priority score: {f.priority_score}\n\n"
                f"Remediation:\n{f.remediation or 'Review and remediate.'}"
            )
        result = self.create_security_issue(
            summary=summary,
            description=description,
            severity=severity,
            labels=["security", "cyberguard"],
        )
        key = result.get("key")
        if key and not result.get("error"):
            self.link_cve_to_finding(finding_id, key)
        return {**result, "finding_id": finding_id}

    def create_security_issue(
        self,
        *,
        summary: str,
        description: str,
        severity: str = "medium",
        labels: list[str] | None = None,
        cve_ids: list[str] | None = None,
    ) -> dict:
        due = (datetime.now(timezone.utc) + timedelta(days=_SLA_DAYS.get(severity, 90))).date().isoformat()
        fields = {
            "project": {"key": self.project_key},
            "summary": summary[:250],
            "description": description + (f"\n\nCVEs: {', '.join(cve_ids)}" if cve_ids else ""),
            "issuetype": {"name": "Bug"},
            "priority": {"name": _PRIORITY.get(severity, "Medium")},
            "labels": (labels or []) + [f"severity-{severity}"],
            "duedate": due,
        }
        if not self.enabled:
            key = f"{self.project_key}-LOCAL-{abs(hash(summary)) % 10000}"
            logger.info("Jira disabled; simulated issue %s", key)
            return {"key": key, "simulated": True, "due": due, "summary": summary}
        try:
            r = httpx.post(
                f"{self.base}/rest/api/2/issue",
                json={"fields": fields},
                auth=self.auth,
                timeout=15.0,
            )
            r.raise_for_status()
            data = r.json()
            return {"key": data["key"], "url": f"{self.base}/browse/{data['key']}", "due": due}
        except httpx.HTTPError as exc:
            logger.warning("Jira issue creation failed: %s", exc)
            return {"error": str(exc), "simulated": False}

    def link_cve_to_finding(self, finding_id: str, jira_key: str) -> None:
        with session_scope() as db:
            f = db.get(SecurityFinding, finding_id)
            if f:
                f.jira_key = jira_key

    def sla_report(self, org_id: str) -> dict:
        now = datetime.now(timezone.utc)
        breaches, at_risk = [], []
        with session_scope() as db:
            rows = db.query(SecurityFinding).filter(
                SecurityFinding.org_id == org_id,
                SecurityFinding.status.in_(("open", "triaged")),
            ).all()
            for f in rows:
                created = f.created_at.replace(tzinfo=timezone.utc) if f.created_at.tzinfo is None else f.created_at
                deadline = created + timedelta(days=_SLA_DAYS.get(f.severity, 90))
                age_days = (now - created).days
                item = {"id": f.id, "title": f.title, "severity": f.severity, "age_days": age_days, "jira_key": f.jira_key}
                if now > deadline:
                    breaches.append(item)
                elif now > deadline - timedelta(days=3):
                    at_risk.append(item)
        return {"sla_breaches": breaches, "at_risk": at_risk, "checked_at": now.isoformat()}

    def _transition(self, jira_key: str, target: str = "Done") -> bool:
        try:
            r = httpx.get(
                f"{self.base}/rest/api/2/issue/{jira_key}/transitions", auth=self.auth, timeout=10.0
            )
            r.raise_for_status()
            for tr in r.json().get("transitions", []):
                if tr["name"].lower() in (target.lower(), "done", "close", "resolve"):
                    httpx.post(
                        f"{self.base}/rest/api/2/issue/{jira_key}/transitions",
                        json={"transition": {"id": tr["id"]}},
                        auth=self.auth,
                        timeout=10.0,
                    )
                    return True
        except httpx.HTTPError as exc:
            logger.warning("Jira transition failed for %s: %s", jira_key, exc)
        return False

    def close_resolved_tickets(self, org_id: str) -> dict:
        """Close the Jira ticket for any finding that is fixed / no longer open."""
        closed = 0
        with session_scope() as db:
            rows = db.query(SecurityFinding).filter(
                SecurityFinding.org_id == org_id,
                SecurityFinding.jira_key.is_not(None),
                SecurityFinding.status.in_(("fixed", "accepted")),
            ).all()
            keys = [(r.jira_key, r.title) for r in rows]
        if not self.enabled:
            return {"closed": 0, "would_close": [k for k, _ in keys], "reason": "jira disabled"}
        for key, title in keys:
            try:
                httpx.post(
                    f"{self.base}/rest/api/2/issue/{key}/comment",
                    json={"body": f"Resolved by CyberGuard AI — '{title}' no longer detected."},
                    auth=self.auth, timeout=10.0,
                )
            except httpx.HTTPError:
                pass
            if self._transition(key, "Done"):
                closed += 1
        return {"closed": closed}

    def sync_remediation_progress(self, org_id: str) -> dict:
        """Pull Jira status for linked findings and reflect resolved ones."""
        if not self.enabled:
            return {"synced": 0, "reason": "jira disabled"}
        synced = 0
        with session_scope() as db:
            rows = db.query(SecurityFinding).filter(
                SecurityFinding.org_id == org_id, SecurityFinding.jira_key.is_not(None)
            ).all()
            for f in rows:
                try:
                    r = httpx.get(
                        f"{self.base}/rest/api/2/issue/{f.jira_key}?fields=status",
                        auth=self.auth, timeout=10.0,
                    )
                    r.raise_for_status()
                    status = r.json()["fields"]["status"]["name"].lower()
                    if status in ("done", "closed", "resolved"):
                        f.status = "fixed"
                        synced += 1
                except httpx.HTTPError:
                    continue
        return {"synced": synced}
