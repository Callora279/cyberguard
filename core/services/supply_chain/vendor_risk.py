"""Score each dependency/vendor for supply-chain risk."""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("supply_chain.vendor_risk")

_COPYLEFT = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-3.0", "SSPL-1.0"}
_PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}


def license_risk(license_id: str) -> tuple[float, str]:
    lid = (license_id or "").upper().replace("LICENSE", "").strip()
    for cl in _COPYLEFT:
        if cl.upper() in lid:
            return 70.0, f"strong copyleft ({cl})"
    for pm in _PERMISSIVE:
        if pm.upper() in lid:
            return 10.0, f"permissive ({pm})"
    if lid in ("", "NOASSERTION", "UNKNOWN", "NONE"):
        return 50.0, "unknown license"
    return 35.0, "non-standard license"


def _github_health(repo: str) -> dict:
    """repo like 'owner/name'. Best-effort; returns {} on failure."""
    if not repo or "/" not in repo:
        return {}
    headers = {"Accept": "application/vnd.github+json"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
    try:
        r = httpx.get(f"https://api.github.com/repos/{repo}", headers=headers, timeout=10.0)
        r.raise_for_status()
        d = r.json()
        pushed = d.get("pushed_at")
        days_since_push = None
        if pushed:
            days_since_push = (
                datetime.now(timezone.utc) - datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            ).days
        return {
            "stars": d.get("stargazers_count", 0),
            "open_issues": d.get("open_issues_count", 0),
            "archived": d.get("archived", False),
            "days_since_last_push": days_since_push,
        }
    except httpx.HTTPError as exc:
        logger.debug("github health lookup failed for %s: %s", repo, exc)
        return {}


def score_component(
    *,
    name: str,
    license: str = "UNKNOWN",
    cve_count: int = 0,
    max_cvss: float = 0.0,
    repo: str = "",
    last_release_days: int | None = None,
) -> dict:
    lic_score, lic_reason = license_risk(license)
    health = _github_health(repo)

    maintenance = 20.0
    dsp = health.get("days_since_last_push")
    ref_days = dsp if dsp is not None else last_release_days
    if ref_days is not None:
        if ref_days > 720:
            maintenance = 85.0
        elif ref_days > 365:
            maintenance = 60.0
        elif ref_days > 180:
            maintenance = 35.0
    if health.get("archived"):
        maintenance = 95.0

    security_history = min(100.0, cve_count * 12.0 + max_cvss * 4.0)
    community = 60.0 if health.get("stars", 1) < 50 else (30.0 if health.get("stars", 0) < 500 else 10.0)

    overall = round(
        maintenance * 0.30
        + security_history * 0.35
        + lic_score * 0.20
        + community * 0.15,
        1,
    )
    return {
        "component": name,
        "risk_score": overall,
        "grade": _grade(overall),
        "factors": {
            "maintenance": round(maintenance, 1),
            "security_history": round(security_history, 1),
            "license": {"score": lic_score, "reason": lic_reason},
            "community_health": round(community, 1),
        },
        "github": health,
    }


def _grade(score: float) -> str:
    if score < 20:
        return "low"
    if score < 45:
        return "moderate"
    if score < 70:
        return "elevated"
    return "high"
