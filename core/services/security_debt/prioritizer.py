"""Score and rank security findings into a remediation backlog."""
from __future__ import annotations

from dataclasses import dataclass

_SEVERITY_WEIGHT = {"critical": 40.0, "high": 28.0, "medium": 16.0, "low": 6.0, "info": 2.0}

# per finding type: (exploitability, business_impact, fix_effort) on 0-10
_TYPE_PROFILE = {
    "secret": (9.0, 9.0, 2.0),
    "dependency": (7.0, 7.0, 3.0),
    "insecure_fn": (6.0, 6.0, 4.0),
    "owasp": (7.0, 8.0, 5.0),
    "debt": (2.0, 4.0, 7.0),
}


@dataclass
class ScoredFinding:
    finding: dict
    priority_score: float
    exploitability: float
    business_impact: float
    fix_effort: float
    rank_reason: str


def _score_one(f: dict) -> ScoredFinding:
    sev = f.get("severity", "medium")
    ftype = f.get("type", "owasp")
    expl, impact, effort = _TYPE_PROFILE.get(ftype, (5.0, 5.0, 5.0))

    # secrets in env/config or with high entropy are worse
    meta = f.get("metadata", {})
    if ftype == "secret" and meta.get("entropy", 0) > 3.5:
        expl = min(10.0, expl + 1.0)
    if f.get("file_path", "").endswith((".env", "config.py", "settings.py")):
        impact = min(10.0, impact + 1.0)

    # priority = severity + exploitability + impact, discounted by effort
    raw = _SEVERITY_WEIGHT.get(sev, 16.0) + expl * 3.0 + impact * 3.0
    score = round(raw / (1.0 + effort / 10.0), 2)
    reason = (
        f"severity={sev}, exploitability={expl}/10, impact={impact}/10, "
        f"effort={effort}/10"
    )
    return ScoredFinding(f, score, expl, impact, effort, reason)


def prioritize(findings: list[dict]) -> list[ScoredFinding]:
    scored = [_score_one(f) for f in findings]
    scored.sort(key=lambda s: s.priority_score, reverse=True)
    return scored


def backlog(findings: list[dict], *, top: int | None = None) -> list[dict]:
    ordered = prioritize(findings)
    if top:
        ordered = ordered[:top]
    return [
        {
            **s.finding,
            "priority_score": s.priority_score,
            "exploitability": s.exploitability,
            "business_impact": s.business_impact,
            "fix_effort": s.fix_effort,
            "rank_reason": s.rank_reason,
            "backlog_position": idx + 1,
        }
        for idx, s in enumerate(ordered)
    ]


def module_score(findings: list[dict]) -> float:
    """0-100 health score for the security-debt module (higher = healthier)."""
    if not findings:
        return 100.0
    penalty = sum(_SEVERITY_WEIGHT.get(f.get("severity", "medium"), 16.0) for f in findings)
    return round(max(0.0, 100.0 - penalty ** 0.5 * 4.0), 2)
