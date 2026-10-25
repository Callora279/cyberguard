"""Gate policy: which scanners run and which severity blocks a merge.

Resolution order for :func:`load_policy`:
    1. the org's most recent ``gate_policies`` row,
    2. the global row (``org_id IS NULL``),
    3. the built-in :class:`GatePolicy` defaults.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.utils.logger import get_logger

logger = get_logger("gate.policy")

# Highest first. "info" is the floor; anything unrecognised ranks with it.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: len(SEVERITY_ORDER) - i for i, s in enumerate(SEVERITY_ORDER)}
# OSV/GHSA and vendor feeds use a few synonyms.
_SEVERITY_ALIASES = {"moderate": "medium", "important": "high", "unknown": "info", "none": "info"}

DEFAULT_SCANNERS = ["supply_chain", "security_debt", "iac"]


def normalize_severity(value: str | None) -> str:
    s = (value or "").strip().lower()
    s = _SEVERITY_ALIASES.get(s, s)
    return s if s in SEVERITY_RANK else "info"


@dataclass
class GatePolicy:
    fail_on: str = "critical"
    scanners: list[str] = field(default_factory=lambda: list(DEFAULT_SCANNERS))
    fail_open: bool = False

    def __post_init__(self) -> None:
        fail_on = (self.fail_on or "").strip().lower()
        fail_on = _SEVERITY_ALIASES.get(fail_on, fail_on)
        if fail_on not in SEVERITY_RANK:
            raise ValueError(f"fail_on must be one of {SEVERITY_ORDER}, got {self.fail_on!r}")
        self.fail_on = fail_on
        self.scanners = [s.strip() for s in (self.scanners or DEFAULT_SCANNERS) if s and s.strip()]


def _from_row(row) -> GatePolicy:
    return GatePolicy(
        fail_on=row.fail_on or "critical",
        scanners=list(row.scanners or DEFAULT_SCANNERS),
        fail_open=bool(row.fail_open),
    )


def load_policy(org_id: str | None) -> GatePolicy:
    """Return the effective gate policy for ``org_id`` (or the global default)."""
    try:
        from sqlalchemy import select

        from core.database.db import session_scope
        from core.database.models import GatePolicyModel

        with session_scope() as db:
            if org_id:
                row = db.scalars(
                    select(GatePolicyModel)
                    .where(GatePolicyModel.org_id == org_id)
                    .order_by(GatePolicyModel.created_at.desc())
                    .limit(1)
                ).first()
                if row:
                    return _from_row(row)
            row = db.scalars(
                select(GatePolicyModel)
                .where(GatePolicyModel.org_id.is_(None))
                .order_by(GatePolicyModel.created_at.desc())
                .limit(1)
            ).first()
            if row:
                return _from_row(row)
    except Exception as exc:  # noqa: BLE001 - a bad/missing policy row must not kill the gate
        logger.warning("could not load gate policy for org=%s (%s); using defaults", org_id, exc)
    return GatePolicy()
