"""LiveScan orchestrator: authorise, fingerprint, match, persist.

assert_authorized runs FIRST — no network request is made until the org has
attested it may scan the target. Findings use the gate's common shape, so they
run through the same evaluator and reporting as every other scanner."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from core.database.db import session_scope
from core.database.models import LiveScanModel
from core.gate.evaluator import GateDecision, evaluate
from core.gate.policy import SEVERITY_ORDER, GatePolicy, normalize_severity
from core.services.livescan import cve_match
from core.services.livescan.authorization import Target, assert_authorized
from core.services.livescan.fingerprint import fingerprint
from core.utils.logger import get_logger

logger = get_logger("livescan.scanner")


@dataclass
class LiveScanResult:
    scan_id: str | None
    target: str
    fingerprint: dict
    findings: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    decision: GateDecision | None = None

    @property
    def reachable(self) -> bool:
        return bool(self.fingerprint.get("reachable"))


async def scan_target(org_id: str, target_url: str) -> LiveScanResult:
    """Authorise, fingerprint and CVE-match a live target; persist the result."""
    target: Target = assert_authorized(org_id, target_url)  # raises before any network call
    scan_url = target.base_url

    fp = await fingerprint(scan_url)
    fp_dict = asdict(fp)

    findings = cve_match.match(fp)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[normalize_severity(f.get("severity"))] += 1

    decision = evaluate(findings, GatePolicy(fail_on="critical"))

    scan_id = None
    try:
        with session_scope() as db:
            row = LiveScanModel(
                org_id=org_id, target=scan_url,
                fingerprint=fp_dict, counts=counts, findings=findings,
            )
            db.add(row)
            db.flush()
            scan_id = row.id
    except Exception as exc:  # noqa: BLE001 - a persistence failure must not lose the scan result
        logger.warning("could not persist livescan org=%s target=%s: %s", org_id, scan_url, exc)

    logger.info("livescan %s: %d finding(s) on %s", decision.decision, len(findings), scan_url)
    return LiveScanResult(
        scan_id=scan_id, target=scan_url, fingerprint=fp_dict,
        findings=findings, counts=counts, decision=decision,
    )
