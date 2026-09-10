"""Background jobs: scans, score recalculation, rotation sweeps, Chakra sync."""
from __future__ import annotations

import httpx

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
    result = score_calculator.calculate(org_id)
    push_score_to_chakra.delay(org_id, result["overall"])
    return result


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
    update_sbom(org_id, repo_path)
    rotate_due_credentials(org_id)
    refresh_fingerprint(org_id)
    return recalculate_risk(org_id)
