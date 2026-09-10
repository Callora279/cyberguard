"""Safely simulate attacks against the digital twin (no traffic to real systems)."""
from __future__ import annotations

from datetime import datetime, timezone

from core.services.cyber_twin import attack_scenarios
from core.utils.logger import get_logger

logger = get_logger("cyber_twin.simulation")


def _sim_sql_injection(twin: dict) -> dict:
    targets = [
        e for e in twin["nodes"]["endpoints"]
        if e["handles_input"] and not e["path"].startswith("/internal")
    ]
    exposed = [e["id"] for e in targets if not e["auth_required"]]
    success = bool(exposed) and bool(twin["nodes"]["data_stores"])
    return {
        "technique": "SQL injection (T1190)",
        "targets_probed": [e["id"] for e in targets],
        "exploitable": exposed,
        "outcome": "data store reachable via unauthenticated input endpoint" if success else "no viable path",
        "success": success,
        "severity": "critical" if success else "low",
    }


def _sim_xss(twin: dict) -> dict:
    reflective = [e["id"] for e in twin["nodes"]["endpoints"] if e["method"] == "GET" and "search" in e["path"].lower()]
    return {
        "technique": "Reflected XSS (T1059.007)",
        "candidates": reflective,
        "success": bool(reflective),
        "outcome": "reflected parameters found" if reflective else "no reflected sinks identified",
        "severity": "high" if reflective else "info",
    }


def _sim_auth_bypass(twin: dict) -> dict:
    unauth_sensitive = [
        e["id"] for e in twin["nodes"]["endpoints"]
        if not e["auth_required"] and any(k in e["path"] for k in ("admin", "user", "account", "config"))
    ]
    return {
        "technique": "Authentication bypass (T1078)",
        "unauthenticated_sensitive_endpoints": unauth_sensitive,
        "success": bool(unauth_sensitive),
        "outcome": "sensitive endpoints exposed without auth" if unauth_sensitive else "sensitive endpoints protected",
        "severity": "critical" if unauth_sensitive else "low",
    }


def _sim_ddos(twin: dict) -> dict:
    internet = twin["topology"]["internet_facing"]
    return {
        "technique": "Volumetric DDoS (T1498)",
        "internet_facing_surface": len(internet),
        "success": len(internet) > 0,
        "outcome": f"{len(internet)} endpoints would absorb load; check rate limiting / CDN",
        "severity": "medium",
    }


def _sim_supply_chain(twin: dict) -> dict:
    return {
        "technique": "Supply-chain compromise (T1195)",
        "success": True,
        "outcome": "a malicious dependency update would execute in the build/runtime context",
        "recommendation": "enforce lockfile pinning, hash verification and SBOM diffing",
        "severity": "high",
    }


_SIMULATORS = {
    "sql_injection": _sim_sql_injection,
    "xss": _sim_xss,
    "auth_bypass": _sim_auth_bypass,
    "ddos": _sim_ddos,
    "supply_chain": _sim_supply_chain,
}


def simulate(twin: dict, attacks: list[str] | None = None, *, scenario: str | None = None) -> dict:
    if scenario:
        attacks = attack_scenarios.get(scenario)["steps"]
    attacks = attacks or list(_SIMULATORS)

    results = []
    for atk in attacks:
        fn = _SIMULATORS.get(atk)
        if not fn:
            results.append({"technique": atk, "success": False, "outcome": "no simulator for technique"})
            continue
        results.append(fn(twin))

    breached = [r for r in results if r.get("success")]
    risk = min(100.0, len(breached) * 25 + sum(20 for r in breached if r.get("severity") == "critical"))
    return {
        "twin": twin["name"],
        "run_at": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario,
        "results": results,
        "successful_techniques": [r["technique"] for r in breached],
        "twin_risk_score": round(risk, 1),
        "verdict": "vulnerable" if risk >= 50 else ("hardened" if risk < 20 else "needs-attention"),
    }
