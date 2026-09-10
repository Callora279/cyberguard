"""Persist scan results and produce summary reports."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, SecurityFinding
from core.services.security_debt import prioritizer, scanner
from core.utils.logger import get_logger

logger = get_logger("security_debt.reporting")


def run_scan_github(
    org_id: str, repo_url: str, *, token: str | None = None, include_dependencies: bool = True
) -> dict:
    """Download a GitHub repo to a temp dir and run the normal scan pipeline."""
    import tempfile

    from core.utils.github import download_repo, parse_repo_url

    repo = parse_repo_url(repo_url)
    with tempfile.TemporaryDirectory(prefix="cg-debt-") as tmp:
        scan_root = str(download_repo(repo, token, Path(tmp)))
        result = run_scan(org_id, scan_root, include_dependencies=include_dependencies)
    result["repo"] = repo
    return result


def run_scan(org_id: str, path: str, *, include_dependencies: bool = True) -> dict:
    raw = [f.as_dict() for f in scanner.scan_path(path)]
    if include_dependencies:
        raw += [f.as_dict() for f in scanner.scan_dependencies(path)]
    backlog = prioritizer.backlog(raw)

    with session_scope() as db:
        # replace open findings for a fresh scan
        db.query(SecurityFinding).filter(
            SecurityFinding.org_id == org_id, SecurityFinding.status == "open"
        ).delete()
        for item in backlog:
            db.add(
                SecurityFinding(
                    org_id=org_id,
                    type=item["type"],
                    title=item["title"],
                    file_path=item.get("file_path", ""),
                    line=item.get("line", 0),
                    severity=item["severity"],
                    priority_score=item["priority_score"],
                    exploitability=item["exploitability"],
                    business_impact=item["business_impact"],
                    fix_effort=item["fix_effort"],
                    remediation=item.get("recommendation") or item.get("rank_reason", ""),
                )
            )
        crit = [i for i in backlog if i["severity"] == "critical"]
        if crit:
            db.add(
                Alert(
                    org_id=org_id,
                    module="security_debt",
                    severity="critical",
                    title=f"{len(crit)} critical security findings",
                    body="; ".join(i["title"] for i in crit[:5]),
                    context={"count": len(crit)},
                )
            )

    return summary(org_id, backlog=backlog)


def summary(org_id: str, *, backlog: list[dict] | None = None) -> dict:
    if backlog is None:
        with session_scope() as db:
            rows = db.scalars(
                select(SecurityFinding).where(
                    SecurityFinding.org_id == org_id, SecurityFinding.status == "open"
                )
            ).all()
            backlog = [
                {
                    "id": r.id, "type": r.type, "title": r.title, "severity": r.severity,
                    "file_path": r.file_path, "line": r.line,
                    "priority_score": r.priority_score,
                }
                for r in rows
            ]
    by_sev = Counter(i["severity"] for i in backlog)
    by_type = Counter(i["type"] for i in backlog)
    return {
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(backlog),
        "by_severity": dict(by_sev),
        "by_type": dict(by_type),
        "module_score": prioritizer.module_score(backlog),
        "top_10": sorted(backlog, key=lambda i: i.get("priority_score", 0), reverse=True)[:10],
    }
