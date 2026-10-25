"""Persist IaC scans (``iac_scans``) and turn them into a risk-score pillar."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import IacScanModel
from core.gate.policy import SEVERITY_ORDER
from core.services.iac_scan import scanner
from core.utils.logger import get_logger

logger = get_logger("iac_scan.reporting")

# Keep stored rows bounded; counts always cover every finding.
_MAX_STORED_FINDINGS = 500
_PENALTY = {"critical": 25, "high": 15, "medium": 6, "low": 2, "info": 0}


def counts(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def module_score(by_severity: dict[str, int]) -> float:
    """Same curve as the supply-chain pillar: 100 - 5*sqrt(weighted penalty)."""
    penalty = sum(_PENALTY.get(sev, 0) * n for sev, n in by_severity.items())
    return round(max(0.0, 100.0 - penalty ** 0.5 * 5.0), 2)


def _persist(org_id: str, target: str, kind: str, findings: list[dict]) -> dict:
    by_sev = counts(findings)
    with session_scope() as db:
        db.add(
            IacScanModel(
                org_id=org_id,
                target=target[:512],
                kind=kind,
                counts=by_sev,
                findings=findings[:_MAX_STORED_FINDINGS],
            )
        )
    return {
        "org_id": org_id,
        "target": target,
        "kind": kind,
        "total_findings": len(findings),
        "by_severity": by_sev,
        "module_score": module_score(by_sev),
    }


def run_scan(org_id: str, path: str | Path, *, target: str | None = None) -> dict:
    """Config-scan ``path`` and record it. ``target`` labels it (e.g. the repo)."""
    return _persist(org_id, target or str(path), "config", scanner.scan(path))


def run_image_scan(org_id: str, refs: Iterable[str]) -> list[dict]:
    return [_persist(org_id, ref, "image", scanner.scan_images([ref])) for ref in refs]


def summary(org_id: str) -> dict | None:
    """Latest config scan + latest scan per image, or None if never scanned."""
    with session_scope() as db:
        rows = db.scalars(
            select(IacScanModel)
            .where(IacScanModel.org_id == org_id)
            .order_by(IacScanModel.created_at.desc())
        ).all()
        latest: dict[tuple[str, str], dict] = {}
        for r in rows:
            # one repo per org today, so the newest config scan wins regardless of target
            key = ("config", "") if r.kind == "config" else ("image", r.target)
            latest.setdefault(key, dict(r.counts or {}))
    if not latest:
        return None
    by_sev = {s: sum(c.get(s, 0) for c in latest.values()) for s in SEVERITY_ORDER}
    return {
        "org_id": org_id,
        "scans": len(latest),
        "total_findings": sum(by_sev.values()),
        "by_severity": by_sev,
        "module_score": module_score(by_sev),
    }
