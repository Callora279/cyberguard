"""GitLab agent: same responsibilities as the GitHub agent, GitLab API."""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

import httpx

from core.services.security_debt import reporting as debt_reporting
from core.services.security_debt.scanner import _SECRET_PATTERNS
from core.services.supply_chain import alerts as sc_alerts
from core.services.supply_chain.ai_generated_sbom import sbom_updater
from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("agents.gitlab")

_API = "https://gitlab.com/api/v4"


class GitLabAgent:
    def __init__(self, token: str | None = None) -> None:
        self.token = token or settings.GITLAB_TOKEN
        self._client = httpx.Client(
            base_url=_API,
            headers={"PRIVATE-TOKEN": self.token} if self.token else {},
            timeout=20.0,
        )

    def scan_commit(self, project_id: str, sha: str) -> list[dict]:
        r = self._client.get(f"/projects/{project_id}/repository/commits/{sha}/diff")
        r.raise_for_status()
        findings = []
        for d in r.json():
            for line in (d.get("diff", "") or "").splitlines():
                if not line.startswith("+"):
                    continue
                for name, pat in _SECRET_PATTERNS.items():
                    if re.search(pat, line):
                        findings.append(
                            {"project": project_id, "sha": sha, "file": d.get("new_path"), "detector": name}
                        )
        return findings

    def scan_push(self, payload: dict, org_id: str) -> dict:
        project_id = str(payload["project"]["id"])
        secrets: list[dict] = []
        for commit in payload.get("commits", []):
            secrets += self.scan_commit(project_id, commit["id"])
        sbom = self._update_sbom(project_id, org_id, payload.get("after"))
        return {"project": project_id, "secrets_found": secrets, "sbom": sbom}

    def scan_merge_request(self, project_id: str, mr_iid: int, org_id: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            mr = self._client.get(f"/projects/{project_id}/merge_requests/{mr_iid}").json()
            self._download_archive(project_id, mr["sha"], Path(tmp))
            debt = debt_reporting.run_scan(org_id, tmp)
            supply = sc_alerts.run_scan(org_id, tmp)
        self._comment_mr(
            project_id,
            mr_iid,
            f"**CyberGuard AI scan** — {debt['total_findings']} findings, "
            f"{supply['critical_or_high']} high/critical CVEs",
        )
        return {"debt": debt, "supply": supply}

    def _update_sbom(self, project_id: str, org_id: str, sha: str | None) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                self._download_archive(project_id, sha or "HEAD", Path(tmp))
                return sbom_updater.update(org_id, tmp, commit=sha)
            except Exception as exc:  # noqa: BLE001
                return {"changed": False, "error": str(exc)}

    def _download_archive(self, project_id: str, sha: str, dest: Path) -> None:
        r = self._client.get(f"/projects/{project_id}/repository/archive.tar.gz", params={"sha": sha})
        r.raise_for_status()
        archive = dest / "src.tar.gz"
        archive.write_bytes(r.content)
        import tarfile

        with tarfile.open(archive) as tf:
            tf.extractall(dest)  # noqa: S202

    def _comment_mr(self, project_id: str, mr_iid: int, body: str) -> None:
        if not self.token:
            logger.info("no token; would comment on MR %s!%s", project_id, mr_iid)
            return
        self._client.post(f"/projects/{project_id}/merge_requests/{mr_iid}/notes", json={"body": body})


def handle_webhook(event: str, payload: dict, org_id: str) -> dict:
    agent = GitLabAgent()
    if event == "Push Hook":
        return agent.scan_push(payload, org_id)
    if event == "Merge Request Hook" and payload.get("object_attributes", {}).get("action") in ("open", "update"):
        oa = payload["object_attributes"]
        return agent.scan_merge_request(str(payload["project"]["id"]), oa["iid"], org_id)
    return {"ignored": event}
