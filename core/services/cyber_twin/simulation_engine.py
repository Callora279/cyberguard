"""Safely simulate attacks against the digital twin (no traffic to real systems)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from core.services import ai_client
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


def _sim_brute_force(twin: dict) -> dict:
    flows = [f for f in twin["nodes"]["auth_flows"] if f.get("type") == "credential"]
    success = bool(flows)
    return {
        "technique": "Brute-force authentication (T1110)",
        "credential_endpoints": [f["id"] for f in flows],
        "success": success,
        "outcome": "login form(s) found with no observable rate-limiting or lockout signal"
        if success else "no credential-based login found",
        "severity": "high" if success else "info",
    }


_SENSITIVE_PATH_HINTS = ("env", "config", "debug", ".git", "swagger", "api-docs", "backup", "secret", "key")


def _sim_api_key_exposure(twin: dict) -> dict:
    endpoints = twin["nodes"]["endpoints"]
    exposed = [
        e["id"] for e in endpoints
        if not e["auth_required"] and any(s in e["path"].lower() for s in _SENSITIVE_PATH_HINTS)
    ]
    if not exposed:
        exposed = [e["id"] for e in endpoints if e.get("is_api") and not e["auth_required"]]
    return {
        "technique": "API key / secret exposure check (T1552)",
        "exposed_candidates": exposed,
        "success": bool(exposed),
        "outcome": f"{len(exposed)} unauthenticated endpoint(s) may leak configuration or keys"
        if exposed else "no obviously exposed config/secret endpoints",
        "severity": "critical" if exposed else "low",
    }


def _sim_csrf(twin: dict) -> dict:
    state_changing = [
        e["id"] for e in twin["nodes"]["endpoints"]
        if e["method"] in ("POST", "PUT", "PATCH", "DELETE") and not e.get("is_login_form")
    ]
    success = bool(state_changing)
    return {
        "technique": "Cross-Site Request Forgery (CSRF)",
        "state_changing_endpoints": state_changing,
        "success": success,
        "outcome": "state-changing endpoints found; verify CSRF tokens / SameSite cookies are enforced"
        if success else "no state-changing endpoints discovered",
        "severity": "high" if success else "info",
    }


_FILE_PATH_HINTS = ("file", "download", "path", "doc", "asset", "static", "export", "report")


def _sim_directory_traversal(twin: dict) -> dict:
    candidates = [e["id"] for e in twin["nodes"]["endpoints"] if any(k in e["path"].lower() for k in _FILE_PATH_HINTS)]
    success = bool(candidates)
    return {
        "technique": "Directory traversal (T1083 / path manipulation)",
        "candidate_endpoints": candidates,
        "success": success,
        "outcome": "file-serving endpoints found; verify path canonicalisation and allow-listing"
        if success else "no file-serving endpoints discovered",
        "severity": "high" if success else "info",
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
    "brute_force": _sim_brute_force,
    "api_key_exposure": _sim_api_key_exposure,
    "csrf": _sim_csrf,
    "directory_traversal": _sim_directory_traversal,
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


# ---------------------------------------------------------------------------
# AI-narrated simulation (Phase 3): the heuristic engine above stays the
# ground truth for *what's actually exploitable* (it only reasons over the
# twin's real structure); this asks the org's AI provider to turn that into
# an attacker narrative for the report. Falls back to a heuristic-derived
# narrative if the AI call fails — a simulation run must never 500 just
# because the model is unreachable.
# ---------------------------------------------------------------------------
def simulate_with_ai(twin: dict, scenario_id: str, *, org_id: str) -> dict:
    scenario = attack_scenarios.get(scenario_id)
    heuristic = simulate(twin, scenario=scenario_id)

    app_structure = {
        "name": twin["name"],
        "endpoint_count": twin["stats"]["endpoint_count"],
        "unauthenticated_endpoints": twin["stats"]["unauthenticated_endpoints"],
        "sample_endpoints": [
            {"method": e["method"], "path": e["path"], "auth_required": e["auth_required"]}
            for e in twin["nodes"]["endpoints"][:30]
        ],
        "auth_flows": [f["path"] for f in twin["nodes"]["auth_flows"]][:10],
        "data_stores": [s.get("type", s.get("id")) for s in twin["nodes"]["data_stores"]],
    }
    prompt = (
        "Given this web application structure:\n"
        f"{json.dumps(app_structure, indent=2)}\n\n"
        f"Simulate an attacker performing:\n{scenario['name']}\n\n"
        "Describe step by step what the attacker would try, what they might find, "
        "and what defences are needed.\n\n"
        "Respond with ONLY a JSON object of this exact shape: "
        '{"attack_steps": ["...", ...], "vulnerabilities_found": ["...", ...], '
        '"exploitation_difficulty": "low|medium|high", "recommended_defences": ["...", ...]}'
    )
    try:
        record = ai_client.chat_for_org(
            org_id,
            prompt,
            system="You are a penetration tester documenting a safe, non-destructive attack "
            "simulation against a client's application for a security report. Respond with valid JSON only.",
            temperature=0.4,
            max_tokens=1200,
            purpose="cyber_twin_simulation",
            json_mode=True,
        )
        try:
            result = json.loads(record.response)
        except json.JSONDecodeError:
            start, end = record.response.find("{"), record.response.rfind("}")
            if not (0 <= start < end):
                raise
            result = json.loads(record.response[start : end + 1])
        analysis = {
            "attack_steps": [str(s) for s in result.get("attack_steps", [])][:12],
            "vulnerabilities_found": [str(s) for s in result.get("vulnerabilities_found", [])][:12],
            "exploitation_difficulty": str(result.get("exploitation_difficulty", "unknown")),
            "recommended_defences": [str(s) for s in result.get("recommended_defences", [])][:12],
            "source": "ai",
            "provider": record.metadata.get("provider", "groq"),
            "model": record.model,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI cyber-twin simulation failed for scenario=%s: %s", scenario_id, exc)
        analysis = {
            "attack_steps": [f"Probe {r['technique']}" for r in heuristic["results"]],
            "vulnerabilities_found": [r["outcome"] for r in heuristic["results"] if r.get("success")],
            "exploitation_difficulty": "low" if heuristic["twin_risk_score"] >= 50 else "medium",
            "recommended_defences": ["AI analysis unavailable — re-run once the AI provider is reachable."],
            "source": "heuristic",
        }

    return {**heuristic, "scenario_name": scenario["name"], "ai_analysis": analysis}
