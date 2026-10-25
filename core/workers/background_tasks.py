"""Background jobs: scans, score recalculation, rotation sweeps, Chakra sync."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

import httpx
from sqlalchemy import select

from core.database.db import session_scope
from core.services.ai_governance.ai_behavior_fingerprinting import fingerprint_generator, fingerprint_store
from core.services.machine_identity import credential_rotation, identity_registry
from core.services.security_debt import reporting as debt_reporting
from core.services.supply_chain import alerts as sc_alerts
from core.services.supply_chain.ai_generated_sbom import sbom_updater
from core.services.unified_risk_score import score_calculator
from core.utils.config import settings
from core.utils.logger import get_logger
from core.workers.queue import task

logger = get_logger("workers.tasks")


@task("cyberguard.security_debt_scan")
def security_debt_scan(org_id: str, path: str) -> dict:
    return debt_reporting.run_scan(org_id, path)


@task("cyberguard.supply_chain_scan")
def supply_chain_scan(org_id: str, path: str) -> dict:
    return sc_alerts.run_scan(org_id, path)


@task("cyberguard.iac_scan")
def iac_scan(org_id: str, path: str) -> dict:
    from core.services.iac_scan import reporting as iac_reporting

    return iac_reporting.run_scan(org_id, path)


@task("cyberguard.update_sbom")
def update_sbom(org_id: str, path: str, commit: str | None = None) -> dict:
    return sbom_updater.update(org_id, path, commit=commit)


@task("cyberguard.rotate_due_credentials")
def rotate_due_credentials(org_id: str) -> dict:
    identity_registry.check_expiries(org_id)
    return credential_rotation.rotate_due(org_id)


@task("cyberguard.daily_identity_sweep")
def daily_identity_sweep(org_id: str) -> dict:
    """Runs daily at midnight: expiry, <30-day expiry notice, staleness."""
    from core.services.machine_identity import behaviour_monitor

    expiry = identity_registry.check_expiries(org_id)
    expiring = credential_rotation.notify_expiring(org_id, within_days=30)
    stale = behaviour_monitor.check_stale(org_id, days=30)
    return {
        "org_id": org_id,
        "expired": len(expiry["expired"]),
        "expiring_soon": len(expiring["expiring"]),
        "stale": len(stale["stale"]),
    }


@task("cyberguard.refresh_fingerprint")
def refresh_fingerprint(org_id: str) -> dict:
    fp = fingerprint_generator.generate(org_id)
    fingerprint_store.save(org_id, fp)
    return {"org_id": org_id, "sample_size": fp["sample_size"]}


@task("cyberguard.recalculate_risk")
def recalculate_risk(org_id: str) -> dict:
    from core.database.models import RiskScore

    with session_scope() as db:
        prev = db.scalars(
            select(RiskScore)
            .where(RiskScore.org_id == org_id)
            .order_by(RiskScore.timestamp.desc())
            .limit(1)
        ).first()
        before = prev.overall if prev else None

    result = score_calculator.calculate(org_id)
    push_score_to_chakra.delay(org_id, result["overall"])

    if before is not None:
        try:
            from core.services.notifications import dispatcher

            dispatcher.notify_risk_change(org_id, before, result["overall"])
        except Exception:  # noqa: BLE001
            logger.exception("risk-change notification failed for %s", org_id)
    return result


@task("cyberguard.send_daily_digest")
def send_daily_digest(org_id: str) -> dict:
    from core.services.notifications import dispatcher

    return dispatcher.notify_daily_summary(org_id)


@task("cyberguard.send_weekly_report")
def send_weekly_report(org_id: str) -> dict:
    from core.services.notifications import dispatcher

    return dispatcher.notify_weekly_digest(org_id)


@task("cyberguard.check_new_cves")
def check_new_cves(org_id: str) -> dict:
    """Re-run the OSV/NVD scan against the org's connected repo to surface new CVEs."""
    from core.database.models import OrgSettings

    with session_scope() as db:
        row = db.get(OrgSettings, org_id)
        repo_url = row.github_repo_url if row else None
        token = row.github_token if row else None
    if not repo_url:
        return {"org_id": org_id, "skipped": "no connected repo"}
    try:
        from core.utils.github import download_repo, parse_repo_url

        with tempfile.TemporaryDirectory(prefix="cg-cve-") as tmp:
            root = str(download_repo(parse_repo_url(repo_url), token, Path(tmp)))
            return sc_alerts.run_scan(org_id, root)
    except Exception as exc:  # noqa: BLE001
        logger.info("CVE check skipped for %s: %s", org_id, exc)
        return {"org_id": org_id, "error": str(exc)}


@task("cyberguard.push_score_to_chakra")
def push_score_to_chakra(org_id: str, score: float) -> dict:
    """Report the security score to Chakra Intelligence."""
    try:
        resp = httpx.get(
            "http://chakra-internal/internal/health-score",
            params={"chakra_org_id": settings.CHAKRA_ORG_ID},
            headers={"X-Sync-Secret": settings.INTERNAL_SYNC_SECRET},
            timeout=8.0,
        )
        return {"pushed": True, "status": resp.status_code}
    except httpx.HTTPError as exc:
        logger.info("Chakra push skipped: %s", exc)
        return {"pushed": False, "error": str(exc)}


@task("cyberguard.full_org_sweep")
def full_org_sweep(org_id: str, repo_path: str) -> dict:
    security_debt_scan(org_id, repo_path)
    supply_chain_scan(org_id, repo_path)
    iac_scan(org_id, repo_path)
    update_sbom(org_id, repo_path)
    rotate_due_credentials(org_id)
    refresh_fingerprint(org_id)
    return recalculate_risk(org_id)


# ---- continuous security gate ---------------------------------------------

_GATE_STATUS_CONTEXT = "cyberguard/gate"
_GATE_CLONE_TIMEOUT = 300


def _gate_token(provider: str, org_id: str | None) -> str:
    """Org-level GitHub token if configured, else the global agent token."""
    if provider == "github" and org_id:
        from core.database.models import OrgSettings

        with session_scope() as db:
            row = db.get(OrgSettings, org_id)
            if row and row.github_token:
                return row.github_token
    return settings.GITHUB_TOKEN if provider == "github" else settings.GITLAB_TOKEN


def _gate_clone_url(provider: str, repo: str, token: str) -> str:
    # Host is fixed (never taken from the payload) so the token can only go to
    # the SCM it was issued for.
    if provider == "github":
        cred = f"x-access-token:{quote(token, safe='')}@" if token else ""
        return f"https://{cred}github.com/{repo}.git"
    cred = f"oauth2:{quote(token, safe='')}@" if token else ""
    return f"https://{cred}gitlab.com/{repo}.git"


def _gate_git(args: list[str], *, cwd: str | None, token: str) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=_GATE_CLONE_TIMEOUT
    )
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        if token:
            msg = msg.replace(token, "***").replace(quote(token, safe=""), "***")
        raise RuntimeError(f"git {args[0]} failed: {msg[-300:]}")
    return proc.stdout.strip()


def _gate_shallow_clone(provider: str, repo: str, ref: str, sha: str, token: str, dest: str) -> None:
    """``git clone --depth 1 --branch <ref>`` and make sure HEAD is ``sha``."""
    if not ref or ref.startswith("-"):
        raise RuntimeError(f"refusing to clone suspicious ref {ref!r}")
    url = _gate_clone_url(provider, repo, token)
    _gate_git(["clone", "--depth", "1", "--single-branch", "--branch", ref, "--", url, dest], cwd=None, token=token)
    if sha and _gate_git(["rev-parse", "HEAD"], cwd=dest, token=token) != sha:
        # The branch moved since the event fired; scan the commit the status is for.
        _gate_git(["fetch", "--depth", "1", "origin", sha], cwd=dest, token=token)
        _gate_git(["checkout", "--detach", "FETCH_HEAD"], cwd=dest, token=token)


def _gate_resolve_event(payload: dict) -> dict:
    """Pull the fields the gate needs out of the normalised webhook event."""
    provider = payload.get("provider")
    if provider not in ("github", "gitlab"):
        raise ValueError(f"unsupported provider {provider!r}")
    ev = {
        "provider": provider,
        "event": payload.get("event") or "push",
        "org_id": payload.get("org_id"),
        "repo": payload.get("repo") or "",
        "project_id": str(payload.get("project_id") or ""),
        "clone_repo": payload.get("clone_repo") or payload.get("repo") or "",
        "ref": payload.get("ref") or "",
        "commit_sha": payload.get("commit_sha") or "",
    }
    if not ev["clone_repo"] or not ev["ref"] or not ev["commit_sha"]:
        raise ValueError("event is missing repo, ref or commit_sha")
    if provider == "gitlab" and not ev["project_id"]:
        raise ValueError("gitlab event is missing project_id")
    return ev


@task("cyberguard.run_gate_for_event")
def run_gate_for_event(payload: dict) -> dict:
    """Clone the pushed ref, run the security gate and report back to the SCM."""
    from core.database.models import GateRunModel
    from core.gate.evaluator import evaluate
    from core.gate.policy import load_policy
    from core.gate.runner import run_gate

    ev = _gate_resolve_event(payload)
    provider, org_id, sha = ev["provider"], ev["org_id"], ev["commit_sha"]
    token = _gate_token(provider, org_id)
    target_url = f"{settings.FRONTEND_URL.rstrip('/')}/security-debt"

    if provider == "github":
        from agents.github.github_agent import GitHubAgent

        agent = GitHubAgent(token=token)

        def post(state: str, desc: str) -> None:
            agent.post_commit_status(ev["repo"], sha, state, desc, target_url, context=_GATE_STATUS_CONTEXT)
    else:
        from agents.gitlab.gitlab_agent import GitLabAgent

        agent = GitLabAgent(token=token)

        def post(state: str, desc: str) -> None:
            agent.post_commit_status(ev["project_id"], sha, state, desc, target_url, name=_GATE_STATUS_CONTEXT)

    policy = load_policy(org_id)
    post("pending", "CyberGuard security gate running…")

    tmp = tempfile.mkdtemp(prefix="cg-gate-")
    try:
        try:
            src = str(Path(tmp) / "src")
            _gate_shallow_clone(provider, ev["clone_repo"], ev["ref"], sha, agent.token, src)
            decision = run_gate(src, policy).decision
        except Exception as exc:  # noqa: BLE001 - infra failure; fail_open decides
            logger.warning("gate run failed for %s %s@%s: %s", provider, ev["repo"], sha, exc)
            decision = evaluate([], policy, [f"gate infrastructure error: {exc}"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    try:
        with session_scope() as db:
            db.add(
                GateRunModel(
                    org_id=org_id,
                    provider=provider,
                    repo=ev["repo"],
                    ref=ev["ref"],
                    commit_sha=sha,
                    event=ev["event"],
                    decision=decision.decision,
                    counts=decision.summary,
                    reasons=decision.reasons,
                )
            )
    except Exception as exc:  # noqa: BLE001 - still report status to the SCM
        logger.warning("could not persist gate run for %s@%s: %s", ev["repo"], sha, exc)

    description = decision.short_description()
    post("success" if decision.passed else "failure", description)
    return {
        "provider": provider,
        "repo": ev["repo"],
        "commit_sha": sha,
        "decision": decision.decision,
        "passed": decision.passed,
        "counts": decision.summary,
        "description": description,
    }
