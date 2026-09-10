"""Zero-trust access decisions: never trust, always verify.

Every access request is scored on identity health, behavioural anomaly,
requested privilege vs granted scope, device/network posture and freshness of
authentication. The engine returns allow / step-up / deny.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.services.machine_identity import behaviour_monitor, identity_registry
from core.services.machine_identity.identity_dna import dna_analyzer
from core.utils.logger import get_logger

logger = get_logger("machine_identity.zero_trust")


@dataclass
class AccessRequest:
    identity_id: str
    org_id: str
    resource: str
    action: str  # read | write | admin
    ip: str = ""
    geo: str = ""
    device_managed: bool = False
    mfa_present: bool = False
    auth_age_seconds: int = 0


@dataclass
class AccessDecision:
    decision: str  # allow | step_up | deny
    trust_score: float
    factors: dict = field(default_factory=dict)
    obligations: list[str] = field(default_factory=list)


_PRIV_RANK = {"read": 1, "write": 2, "admin": 3}


def evaluate(req: AccessRequest) -> AccessDecision:
    factors: dict[str, float] = {}

    try:
        identity = identity_registry.get(req.identity_id)
    except KeyError:
        return AccessDecision("deny", 0.0, {"identity": "unknown"}, ["identity not registered"])

    if identity["status"] in ("revoked", "expired"):
        return AccessDecision("deny", 0.0, {"identity_status": identity["status"]}, ["credential inactive"])

    # 1. least privilege
    granted = max((_PRIV_RANK.get(s, 1) for s in identity["scopes"]), default=1)
    requested = _PRIV_RANK.get(req.action, 1)
    factors["least_privilege"] = 100.0 if requested <= granted else 0.0

    # 2. behavioural anomaly
    anomaly = behaviour_monitor.observe(
        {
            "identity_id": req.identity_id,
            "org_id": req.org_id,
            "ip": req.ip,
            "geo": req.geo,
            "resource": req.resource,
            "action": req.action,
            "privileged": req.action in ("write", "admin"),
            "hour": datetime.now(timezone.utc).hour,
        }
    )
    factors["behaviour"] = 100.0 - anomaly["risk_score"]

    # 3. identity DNA integrity
    dna = dna_analyzer.analyze(req.identity_id, live_signal={"ip": req.ip, "geo": req.geo, "action": req.action})
    factors["identity_dna"] = 100.0 - dna.get("compromise_score", 0.0)

    # 4. device / network posture
    factors["device_posture"] = 100.0 if req.device_managed else 40.0

    # 5. authentication freshness + MFA
    fresh = req.auth_age_seconds <= 3600
    factors["auth_freshness"] = (60.0 if fresh else 20.0) + (40.0 if req.mfa_present else 0.0)

    weights = {
        "least_privilege": 0.30,
        "behaviour": 0.25,
        "identity_dna": 0.20,
        "device_posture": 0.10,
        "auth_freshness": 0.15,
    }
    trust = round(sum(factors[k] * w for k, w in weights.items()), 1)

    obligations: list[str] = []
    if factors["least_privilege"] == 0.0:
        decision = "deny"
        obligations.append("requested privilege exceeds granted scope")
    elif trust >= 75:
        decision = "allow"
    elif trust >= 45:
        decision = "step_up"
        if not req.mfa_present:
            obligations.append("require MFA / re-authentication")
        if anomaly["anomalous"]:
            obligations.append("human approval for anomalous access")
    else:
        decision = "deny"
        obligations.append("trust score below threshold")

    logger.info(
        "zero-trust %s -> %s (trust=%.1f) for %s on %s",
        req.identity_id, decision, trust, req.action, req.resource,
    )
    return AccessDecision(decision, trust, factors, obligations)


def request_access(req: AccessRequest) -> dict:
    d = evaluate(req)
    return {
        "identity_id": req.identity_id,
        "resource": req.resource,
        "action": req.action,
        "decision": d.decision,
        "trust_score": d.trust_score,
        "factors": d.factors,
        "obligations": d.obligations,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
