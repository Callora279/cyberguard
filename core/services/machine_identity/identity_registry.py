"""Register and track non-human identities and their lifecycle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, MachineIdentity
from core.services.machine_identity.identity_dna import dna_generator, dna_store
from core.utils.crypto import sha256_hex
from core.utils.logger import get_logger

logger = get_logger("machine_identity.registry")

VALID_TYPES = {"api_key", "service_account", "cert", "oauth", "ssh_key"}
_EXPIRY_WARN_DAYS = 14


def register(
    org_id: str,
    *,
    identity_type: str,
    name: str,
    owner: str = "",
    scopes: list[str] | None = None,
    secret_material: str | None = None,
    expires_at: datetime | None = None,
) -> dict:
    if identity_type not in VALID_TYPES:
        raise ValueError(f"unknown identity type: {identity_type}")
    fingerprint = sha256_hex(secret_material or f"{name}:{owner}")[:32]

    with session_scope() as db:
        identity = MachineIdentity(
            org_id=org_id,
            type=identity_type,
            name=name,
            owner=owner,
            scopes=scopes or [],
            fingerprint=fingerprint,
            expires_at=expires_at,
            status="active",
        )
        db.add(identity)
        db.flush()
        dna = dna_generator.generate_seed(identity.id, identity_type, scopes or [])
        identity.dna = dna
        iid = identity.id
    dna_store.save(iid, dna)
    logger.info("registered %s identity %s (%s)", identity_type, name, iid)
    return get(iid)


def get(identity_id: str) -> dict:
    with session_scope() as db:
        row = db.get(MachineIdentity, identity_id)
        if not row:
            raise KeyError(identity_id)
        return _to_dict(row)


def list_registry(org_id: str, *, identity_type: str | None = None) -> list[dict]:
    with session_scope() as db:
        stmt = select(MachineIdentity).where(MachineIdentity.org_id == org_id)
        if identity_type:
            stmt = stmt.where(MachineIdentity.type == identity_type)
        return [_to_dict(r) for r in db.scalars(stmt.order_by(MachineIdentity.created_at.desc())).all()]


def record_use(identity_id: str, *, when: datetime | None = None) -> None:
    with session_scope() as db:
        row = db.get(MachineIdentity, identity_id)
        if row:
            row.last_used = when or datetime.now(timezone.utc)


def check_expiries(org_id: str) -> dict:
    """Sweep for expiring / expired identities and raise alerts."""
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=_EXPIRY_WARN_DAYS)
    expiring, expired = [], []
    with session_scope() as db:
        rows = db.scalars(
            select(MachineIdentity).where(
                MachineIdentity.org_id == org_id,
                MachineIdentity.expires_at.is_not(None),
                MachineIdentity.status != "revoked",
            )
        ).all()
        for r in rows:
            exp = r.expires_at
            if exp and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp and exp < now:
                r.status = "expired"
                expired.append(_to_dict(r))
            elif exp and exp < soon:
                r.status = "expiring"
                expiring.append(_to_dict(r))
        if expired or expiring:
            db.add(
                Alert(
                    org_id=org_id,
                    module="machine_identity",
                    severity="high" if expired else "medium",
                    title=f"{len(expired)} expired, {len(expiring)} expiring credentials",
                    body="; ".join(i["name"] for i in (expired + expiring)[:8]),
                    context={"expired": [i["id"] for i in expired], "expiring": [i["id"] for i in expiring]},
                )
            )
    return {"expired": expired, "expiring": expiring}


def revoke(identity_id: str) -> dict:
    with session_scope() as db:
        row = db.get(MachineIdentity, identity_id)
        if not row:
            raise KeyError(identity_id)
        row.status = "revoked"
        return _to_dict(row)


def _to_dict(r: MachineIdentity) -> dict:
    return {
        "id": r.id, "org_id": r.org_id, "type": r.type, "name": r.name,
        "owner": r.owner, "scopes": r.scopes, "fingerprint": r.fingerprint,
        "status": r.status, "created_at": r.created_at,
        "expires_at": r.expires_at, "last_used": r.last_used, "last_rotated": r.last_rotated,
    }
