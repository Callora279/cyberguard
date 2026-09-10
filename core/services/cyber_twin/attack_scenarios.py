"""Pre-built attack scenarios: OWASP Top 10, MITRE ATT&CK, sector-specific."""
from __future__ import annotations

_SCENARIOS = {
    "owasp_top_10": {
        "name": "OWASP Top 10 (2021) sweep",
        "framework": "OWASP",
        "steps": ["auth_bypass", "sql_injection", "xss", "supply_chain"],
        "description": "Exercises A01 (broken access control), A03 (injection), "
        "A06/A08 (vulnerable & outdated components / integrity failures).",
    },
    "mitre_initial_access": {
        "name": "MITRE ATT&CK - Initial Access & Execution",
        "framework": "MITRE ATT&CK",
        "steps": ["sql_injection", "auth_bypass", "supply_chain"],
        "tactics": ["TA0001 Initial Access", "TA0002 Execution"],
        "techniques": ["T1190", "T1078", "T1195"],
    },
    "ddos_resilience": {
        "name": "Availability / DDoS resilience",
        "framework": "MITRE ATT&CK",
        "steps": ["ddos"],
        "techniques": ["T1498", "T1499"],
    },
    "nhs_cyber_incident": {
        "name": "NHS-style cyber incident simulation",
        "framework": "NCSC / DSPT",
        "steps": ["supply_chain", "auth_bypass", "sql_injection", "ddos"],
        "description": "Models a WannaCry-style spillover: third-party compromise "
        "-> lateral movement via weak identity controls -> data store access -> "
        "service disruption. Maps to NHS Data Security & Protection Toolkit.",
    },
    "financial_fraud_path": {
        "name": "Financial-services fraud path",
        "framework": "sector-specific",
        "steps": ["auth_bypass", "xss", "supply_chain"],
        "description": "Account takeover -> session hijack -> fraudulent payment "
        "initiation.",
    },
}


def list_scenarios() -> list[dict]:
    return [{"id": k, **{kk: vv for kk, vv in v.items() if kk != "steps"}, "step_count": len(v["steps"])}
            for k, v in _SCENARIOS.items()]


def get(scenario_id: str) -> dict:
    if scenario_id not in _SCENARIOS:
        raise KeyError(scenario_id)
    return {"id": scenario_id, **_SCENARIOS[scenario_id]}
