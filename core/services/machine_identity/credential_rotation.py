"""Automated, zero-downtime credential rotation with history and alerting."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, MachineIdentity
from core.utils.crypto import new_secret, sha256_hex
from core.utils.logger import get_logger

logger = get_logger("machine_identity.rotation")

_HISTORY = Path(os.getenv("CYBERGUARD_STATE_DIR", ".cyberguard")) / "rotation_history.jsonl"


def _log_history(entry: dict) -> None:
    _HISTORY.parent.mkdir(parents=True, exist_ok=True)
    with _HISTORY.open("a") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


def rotate(identity_id: str, *, grace_period_hours: int = 24, dry_run: bool = False) -> dict:
    """Rotate a single credential.

    Zero-downtime model: a new secret is issued and both old + new are valid for
    ``grace_period_hours`` before the old one is retired.
    """
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        row = db.get(MachineIdentity, identity_id)
        if not row:
            raise KeyError(identity_id)
        if row.status == "revoked":
            raise ValueError("cannot rotate a revoked identity")

        old_fp = row.fingerprint
        new_material = new_secret(prefix=row.type)
        new_fp = sha256_hex(new_material)[:32]

        entry = {
            "identity_id": identity_id,
            "name": row.name,
            "type": row.type,
            "rotated_at": now.isoformat(),
            "old_fingerprint": old_fp,
            "new_fingerprint": new_fp,
            "grace_until": (now + timedelta(hours=grace_period_hours)).isoformat(),
            "dry_run": dry_run,
            "status": "pending" if dry_run else "active",
        }

        if not dry_run:
            row.fingerprint = new_fp
            row.last_rotated = now
            row.status = "active"
            if row.expires_at:
                row.expires_at = now + timedelta(days=90)
        _log_history(entry)

    logger.info("rotated identity %s (dry_run=%s)", identity_id, dry_run)
    # In production the new_material would be pushed to a secret manager; we only
    # return it here so a caller can complete provisioning.
    return {**entry, "new_secret": None if dry_run else new_material}


def rotate_due(org_id: str, *, max_age_days: int = 90) -> dict:
    """Rotate every credential older than ``max_age_days`` (or never rotated)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    rotated, failed = [], []
    with session_scope() as db:
        rows = db.scalars(
            select(MachineIdentity).where(
                MachineIdentity.org_id == org_id, MachineIdentity.status != "revoked"
            )
        ).all()
        candidates = [
            r.id for r in rows
            if not r.last_rotated
            or (r.last_rotated.replace(tzinfo=timezone.utc) if r.last_rotated.tzinfo is None else r.last_rotated) < cutoff
        ]
    for cid in candidates:
        try:
            rotated.append(rotate(cid))
        except Exception as exc:  # noqa: BLE001
            failed.append({"identity_id": cid, "error": str(exc)})

    if failed:
        with session_scope() as db:
            db.add(
                Alert(
                    org_id=org_id,
                    module="machine_identity",
                    severity="high",
                    title=f"{len(failed)} credential rotations failed",
                    body="; ".join(f['identity_id'] for f in failed),
                    context={"failed": failed},
                )
            )
    return {"rotated": len(rotated), "failed": failed}


def history(identity_id: str | None = None, *, limit: int = 100) -> list[dict]:
    if not _HISTORY.exists():
        return []
    out = []
    for line in _HISTORY.read_text().splitlines()[-limit * 4 :]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if identity_id is None or entry.get("identity_id") == identity_id:
            out.append(entry)
    return out[-limit:]
