"""GitHub agent: monitor repos, detect secrets in commits, update SBOM, PR scans."""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

import httpx

from core.services.iac_scan import reporting as iac_reporting
from core.services.security_debt import reporting as debt_reporting
from core.services.security_debt.scanner import _SECRET_PATTERNS
from core.services.supply_chain import alerts as sc_alerts
from core.services.supply_chain.ai_generated_sbom import sbom_updater
from core.services.unified_risk_score import score_calculator
from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("agents.github")

_API = "https://api.github.com"


def _frontend_url() -> str:
    return settings.FRONTEND_URL.rstrip("/")


def _default_branch_pushed(payload: dict) -> bool:
    ref = payload.get("ref", "")
    default = (payload.get("repository") or {}).get("default_branch", "main")
    return ref in (f"refs/heads/{default}", "refs/heads/main", "refs/heads/master")


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
        """Handle a GitHub push webhook payload.

        On a push to the default branch: full security-debt + supply-chain scan
        and a risk-score refresh. On other branches: just secret + SBOM diff.
        """
        repo = payload["repository"]["full_name"]
        secrets = []
        for commit in payload.get("commits", []):
            secrets += self.scan_commit(repo, commit["id"])

        result: dict = {"repo": repo, "secrets_found": secrets}
        sha = payload.get("after")

        if _default_branch_pushed(payload):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    self._download_tarball(repo, sha or "HEAD", Path(tmp))
                    roots = [p for p in Path(tmp).iterdir() if p.is_dir()]
                    root = str(roots[0] if len(roots) == 1 else Path(tmp))
                    result["security_debt"] = debt_reporting.run_scan(org_id, root)
                    result["supply_chain"] = sc_alerts.run_scan(org_id, root)
                    result["iac"] = iac_reporting.run_scan(org_id, root, target=repo)
                    result["sbom"] = sbom_updater.update(org_id, root, commit=sha)
                    result["risk_score"] = score_calculator.calculate(org_id)["overall"]
                except Exception as exc:  # noqa: BLE001
                    logger.warning("push scan failed for %s: %s", repo, exc)
                    result["error"] = str(exc)
        else:
            result["sbom"] = self._update_sbom(repo, org_id, sha)
        return result

    # ---- PR security scan ----------------------------------------------
    _SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    _SEV_ORDER = ["critical", "high", "medium", "low", "info"]

    def scan_pull_request(self, repo: str, pr_number: int, org_id: str) -> dict:
        from core.services.security_debt import scanner

        changed = self._pr_changed_files(repo, pr_number)
        with tempfile.TemporaryDirectory() as tmp:
            head_sha = self._download_pr_head(repo, pr_number, Path(tmp))
            roots = [p for p in Path(tmp).iterdir() if p.is_dir()]
            scan_root = roots[0] if len(roots) == 1 else Path(tmp)
            all_findings = [f.as_dict() for f in scanner.scan_path(scan_root)]

        # scan changed files only (fall back to everything if we can't match)
        findings = [
            f for f in all_findings
            if any(f["file_path"].endswith(c) or c.endswith(f["file_path"]) for c in changed)
        ] or all_findings
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        critical = [f for f in findings if f["severity"] == "critical"]

        report_url = f"{_frontend_url()}/security-debt"
        self._comment_pr(repo, pr_number, self._format_pr_comment(findings, by_sev, report_url))

        state = "failure" if critical else "success"
        desc = (
            f"{len(critical)} critical finding(s) — merge blocked"
            if critical else f"{len(findings)} finding(s), none critical"
        )
        if head_sha:
            self._set_commit_status(repo, head_sha, state, desc, report_url)

        return {
            "pr": pr_number,
            "changed_files": len(changed),
            "findings": len(findings),
            "by_severity": by_sev,
            "critical": len(critical),
            "merge_blocked": bool(critical),
            "commit_status": state,
        }

    def _format_pr_comment(self, findings: list[dict], by_sev: dict, report_url: str) -> str:
        if not findings:
            return (
                "## 🛡️ CyberGuard AI Security Scan\n\n"
                "No new security issues in the changed files. ✅\n\n"
                f"[View full report]({report_url})"
            )
        lines = [f"Found **{len(findings)}** issue(s):", ""]
        shown = 0
        for sev in self._SEV_ORDER:
            for f in [x for x in findings if x["severity"] == sev][:5]:
                loc = f" (line {f['line']})" if f.get("line") else ""
                lines.append(
                    f"{self._SEV_EMOJI.get(sev, '•')} **{sev.capitalize()}**: "
                    f"{f['title']}{loc} — `{f['file_path']}`"
                )
                shown += 1
        if shown < len(findings):
            lines.append(f"…and {len(findings) - shown} more.")
        block = "\n\n> ⛔️ **Merge blocked** — resolve the critical finding(s) above." if by_sev.get("critical") else ""
        return (
            "## 🛡️ CyberGuard AI Security Scan\n\n"
            + "\n".join(lines)
            + block
            + f"\n\n[View full report]({report_url})"
        )

    def _pr_changed_files(self, repo: str, pr_number: int) -> set[str]:
        try:
            files: set[str] = set()
            page = 1
            while True:
                r = self._client.get(
                    f"/repos/{repo}/pulls/{pr_number}/files", params={"per_page": 100, "page": page}
                )
                r.raise_for_status()
                batch = r.json()
                files.update(f["filename"] for f in batch)
                if len(batch) < 100:
                    break
                page += 1
            return files
        except httpx.HTTPError as exc:
            logger.info("could not list PR files for %s#%s: %s", repo, pr_number, exc)
            return set()

    _STATUS_STATES = ("pending", "success", "failure", "error")

    def post_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        target_url: str | None = None,
        context: str = "cyberguard/security",
    ) -> bool:
        """Set a commit status (pending/success/failure/error) on ``repo@sha``.

        Returns True if GitHub accepted it. Never raises on HTTP errors.
        """
        if state not in self._STATUS_STATES:
            raise ValueError(f"state must be one of {self._STATUS_STATES}, got {state!r}")
        if not self.token:
            logger.info("no token; would set %s status=%s on %s@%s", context, state, repo, sha)
            return False
        body = {"state": state, "description": description[:140], "context": context}
        if target_url:
            body["target_url"] = target_url
        try:
            r = self._client.post(f"/repos/{repo}/statuses/{sha}", json=body)
            r.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            logger.warning("failed to set commit status on %s@%s: %s", repo, sha, exc)
            return False

    def _set_commit_status(self, repo: str, sha: str, state: str, description: str, url: str) -> None:
        self.post_commit_status(repo, sha, state, description, url)

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

    def _download_pr_head(self, repo: str, pr_number: int, dest: Path) -> str | None:
        pr = self._client.get(f"/repos/{repo}/pulls/{pr_number}").json()
        sha = (pr.get("head") or {}).get("sha")
        self._download_tarball(repo, sha or "HEAD", dest)
        return sha

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
