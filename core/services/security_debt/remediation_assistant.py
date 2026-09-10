"""AI-powered remediation guidance for security findings."""
from __future__ import annotations

import json

from core.services.ai_governance.real_time_enforcer import guarded_chat
from core.utils.exceptions import CyberGuardError
from core.utils.logger import get_logger

logger = get_logger("security_debt.remediation")

# deterministic fallbacks so the module is useful without the LLM
_PLAYBOOK = {
    "secret": {
        "why": "A credential committed to source code is readable by anyone with "
        "repo access (and anyone it later leaks to); it grants real access until rotated.",
        "fix": "Remove the secret from source, rotate it immediately, and load it "
        "from an environment variable or secret manager. Purge it from git history "
        "(git filter-repo / BFG).",
        "example": "api_key = os.environ['API_KEY']  # not a string literal",
        "eta_minutes": 45,
    },
    "dependency": {
        "why": "A dependency with a known CVE means the vulnerable code path already "
        "ships in your application and can be exploited by anyone who knows the advisory.",
        "fix": "Upgrade to the fixed version and run the test suite; if no fix is "
        "available, apply the advisory's workaround or pin a safe transitive range.",
        "example": "pip install 'package>=<fixed_version>' && pip freeze > requirements.txt",
        "eta_minutes": 30,
    },
    "insecure_fn": {
        "why": "This function passes attacker-influenced input to a dangerous sink "
        "(code execution, deserialisation or a shell), enabling RCE if the input is not trusted.",
        "fix": "Replace the unsafe call with a safe equivalent (ast.literal_eval, "
        "json, hashlib.sha256, subprocess without shell=True, yaml.safe_load).",
        "example": "import ast; value = ast.literal_eval(raw)",
        "eta_minutes": 25,
    },
    "owasp": {
        "why": "This pattern maps to an OWASP Top 10 category — typically injection, "
        "broken transport security or misconfiguration — that is routinely exploited.",
        "fix": "Use parameterised queries / an ORM, encode output, and restrict CORS "
        "to an explicit allow-list over HTTPS.",
        "example": "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
        "eta_minutes": 60,
    },
    "debt": {
        "why": "Concentrated TODO/FIXME markers and oversized files correlate with "
        "defect density; security fixes here are slower and riskier to land.",
        "fix": "Break the hotspot into smaller modules, add tests, and resolve or "
        "ticket each TODO/FIXME.",
        "example": "# split module; add unit tests for each extracted function",
        "eta_minutes": 120,
    },
}


def suggest(finding: dict, *, org_id: str = "unknown", use_ai: bool = True) -> dict:
    base = _PLAYBOOK.get(finding.get("type", "owasp"), _PLAYBOOK["owasp"])
    result = {
        "finding_id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "explanation": base["why"],
        "recommended_fix": base["fix"],
        "code_example": base["example"],
        "estimated_fix_minutes": base["eta_minutes"],
        "source": "playbook",
    }
    if not use_ai:
        return result

    prompt = (
        "You are a senior application-security engineer. Given this finding, return "
        "a JSON object with keys: explanation (string, 2-3 sentences explaining in "
        "plain language what the issue is and why it is a risk in THIS code), "
        "recommended_fix (string), code_example (string, the corrected code), "
        "estimated_fix_minutes (integer), references (array of strings). Be specific "
        "to the language and snippet.\n\n"
        f"{json.dumps(finding, default=str)}"
    )
    try:
        record = guarded_chat(
            prompt,
            org_id=org_id,
            system="Return only valid JSON.",
            purpose="security_debt_remediation",
            max_tokens=800,
        )
        data = json.loads(_extract_json(record.response))
        result.update(
            {
                "explanation": data.get("explanation", result["explanation"]),
                "recommended_fix": data.get("recommended_fix", result["recommended_fix"]),
                "code_example": data.get("code_example", result["code_example"]),
                "estimated_fix_minutes": int(
                    data.get("estimated_fix_minutes", result["estimated_fix_minutes"])
                ),
                "references": data.get("references", []),
                "source": "ai",
            }
        )
    except (CyberGuardError, json.JSONDecodeError, ValueError, KeyError) as exc:
        logger.warning("AI remediation fell back to playbook: %s", exc)
    return result


def create_jira_tickets(scored_findings: list[dict], *, org_id: str = "unknown") -> list[dict]:
    """Turn the top backlog items into Jira issues via the Jira agent."""
    from agents.jira.jira_agent import JiraAgent

    agent = JiraAgent()
    created = []
    for f in scored_findings:
        rec = suggest(f, org_id=org_id, use_ai=False)
        created.append(
            agent.create_security_issue(
                summary=f"[{f.get('severity', 'medium').upper()}] {f.get('title')}",
                description=(
                    f"File: {f.get('file_path')}:{f.get('line')}\n\n"
                    f"{f.get('snippet', '')}\n\nFix: {rec['recommended_fix']}"
                ),
                severity=f.get("severity", "medium"),
                labels=["cyberguard", "security-debt", f.get("type", "misc")],
            )
        )
    return created


def _extract_json(text: str) -> str:
    start, end = text.find("{"), text.rfind("}")
    return text[start : end + 1] if 0 <= start < end else text
