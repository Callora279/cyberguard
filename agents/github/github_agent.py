"""GitHub agent: monitor repos, detect secrets in commits, update SBOM, PR scans."""
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

logger = get_logger("agents.github")

_API = "https://api.github.com"


class GitHubAgent:
    def __init__(self, token: str | None = None) -> None:
        self.token = token or settings.GITHUB_TOKEN
        self._client = httpx.Client(
            base_url=_API,
            headers={
                "Accept": "application/vnd.github+json",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
            timeout=20.0,
        )

    # ---- secret detection -------------------------------------------------
    def scan_commit(self, repo: str, sha: str) -> list[dict]:
        r = self._client.get(f"/repos/{repo}/commits/{sha}")
        r.raise_for_status()
        findings = []
        for f in r.json().get("files", []):
            patch = f.get("patch", "") or ""
            for line in patch.splitlines():
                if not line.startswith("+"):
                    continue
                for name, pat in _SECRET_PATTERNS.items():
                    if re.search(pat, line):
                        findings.append(
                            {"repo": repo, "sha": sha, "file": f["filename"], "detector": name}
                        )
        if findings:
            logger.warning("secrets detected in %s@%s: %d", repo, sha, len(findings))
        return findings

    def scan_push(self, payload: dict, org_id: str) -> dict:
        """Handle a GitHub push webhook payload."""
        repo = payload["repository"]["full_name"]
        secrets = []
        for commit in payload.get("commits", []):
            secrets += self.scan_commit(repo, commit["id"])
        sbom = self._update_sbom(repo, org_id, payload.get("after"))
        return {"repo": repo, "secrets_found": secrets, "sbom": sbom}

    # ---- PR security scan ----------------------------------------------
    def scan_pull_request(self, repo: str, pr_number: int, org_id: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            self._download_pr_head(repo, pr_number, Path(tmp))
            debt = debt_reporting.run_scan(org_id, tmp)
            supply = sc_alerts.run_scan(org_id, tmp)
        self._comment_pr(
            repo,
            pr_number,
            f"### CyberGuard AI scan\n"
            f"- Security debt findings: **{debt['total_findings']}** "
            f"(module score {debt['module_score']})\n"
            f"- Vulnerable dependencies: **{supply['vulnerable_components']}** "
            f"({supply['critical_or_high']} high/critical)\n",
        )
        return {"debt": debt, "supply": supply}

    # ---- helpers ------------------------------------------------------
    def _update_sbom(self, repo: str, org_id: str, sha: str | None) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                self._download_tarball(repo, sha or "HEAD", Path(tmp))
                return sbom_updater.update(org_id, tmp, commit=sha)
            except Exception as exc:  # noqa: BLE001
                logger.info("SBOM update skipped for %s: %s", repo, exc)
                return {"changed": False, "error": str(exc)}

    def _download_tarball(self, repo: str, ref: str, dest: Path) -> None:
        r = self._client.get(f"/repos/{repo}/tarball/{ref}", follow_redirects=True)
        r.raise_for_status()
        archive = dest / "src.tar.gz"
        archive.write_bytes(r.content)
        import tarfile

        with tarfile.open(archive) as tf:
            tf.extractall(dest)  # noqa: S202 - trusted source repo

    def _download_pr_head(self, repo: str, pr_number: int, dest: Path) -> None:
        pr = self._client.get(f"/repos/{repo}/pulls/{pr_number}").json()
        self._download_tarball(repo, pr["head"]["sha"], dest)

    def _comment_pr(self, repo: str, pr_number: int, body: str) -> None:
        if not self.token:
            logger.info("no token; would comment on %s#%s:\n%s", repo, pr_number, body)
            return
        self._client.post(f"/repos/{repo}/issues/{pr_number}/comments", json={"body": body})


def handle_webhook(event: str, payload: dict, org_id: str) -> dict:
    agent = GitHubAgent()
    if event == "push":
        return agent.scan_push(payload, org_id)
    if event == "pull_request" and payload.get("action") in ("opened", "synchronize"):
        return agent.scan_pull_request(
            payload["repository"]["full_name"], payload["number"], org_id
        )
    return {"ignored": event}
