"""Authorisation gate for LiveScan — every scan entrypoint calls
:func:`assert_authorized` before any network request to the target.

A target is scannable only if the org has an ``AuthorizedTargetModel`` row for
that exact host + scheme with ``authorized=True``. Targets that resolve to
private, loopback, link-local or otherwise non-public addresses are refused
even when registered, so the scanner can't be pointed at our own network.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import AuthorizedTargetModel
from core.utils.exceptions import PermissionError_, ValidationError


class NotAuthorizedError(PermissionError_):
    """The target is not an authorised LiveScan target for this organisation."""

    code = "livescan_not_authorized"


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int | None

    @property
    def base_url(self) -> str:
        netloc = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{netloc}{f':{self.port}' if self.port else ''}/"


def parse_target(target_url: str) -> Target:
    """Validate ``target_url`` and split it into scheme / host / port."""
    raw = (target_url or "").strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("target must be an http(s) URL")
    if parsed.username or parsed.password:
        raise ValidationError("target URL must not contain credentials")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ValidationError("target URL has no host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError("target URL has an invalid port") from exc
    return Target(scheme=parsed.scheme, host=host, port=port)


def _assert_public(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise NotAuthorizedError(f"target host '{host}' does not resolve") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise NotAuthorizedError(f"target host '{host}' resolves to a non-public address")


def assert_authorized(org_id: str, target_url: str) -> Target:
    """Return the parsed target if ``org_id`` may scan it, else raise."""
    target = parse_target(target_url)
    with session_scope() as db:
        row = db.scalars(
            select(AuthorizedTargetModel).where(
                AuthorizedTargetModel.org_id == org_id,
                AuthorizedTargetModel.host == target.host,
                AuthorizedTargetModel.scheme == target.scheme,
                AuthorizedTargetModel.authorized.is_(True),
            )
        ).first()
        if row is None:
            raise NotAuthorizedError(
                f"{target.scheme}://{target.host} is not an authorised scan target for this organisation"
            )
    _assert_public(target.host)
    return target


def register_target(org_id: str, target_url: str, *, attested_by: str) -> dict:
    """Record the org's attestation that it may scan ``target_url``."""
    target = parse_target(target_url)
    _assert_public(target.host)
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        row = db.scalars(
            select(AuthorizedTargetModel).where(
                AuthorizedTargetModel.org_id == org_id,
                AuthorizedTargetModel.host == target.host,
                AuthorizedTargetModel.scheme == target.scheme,
            )
        ).first()
        if row is None:
            row = AuthorizedTargetModel(org_id=org_id, host=target.host, scheme=target.scheme)
            db.add(row)
        row.authorized = True
        row.attested_by = attested_by
        row.attested_at = now
        db.flush()
        return {
            "id": row.id,
            "org_id": org_id,
            "host": row.host,
            "scheme": row.scheme,
            "authorized": True,
            "attested_by": attested_by,
            "attested_at": now.isoformat(),
        }
