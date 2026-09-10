"""JWT auth dependency + internal-sync-secret guard."""
from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.utils.config import settings
from core.utils.crypto import verify_jwt
from core.utils.exceptions import AuthError, PermissionError_

_bearer = HTTPBearer(auto_error=False)

_ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class Principal:
    user_id: str
    org_id: str
    email: str
    role: str

    def require_role(self, role: str) -> None:
        if _ROLE_RANK.get(self.role, 0) < _ROLE_RANK.get(role, 99):
            raise PermissionError_(f"role '{role}' required")


async def get_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    token = None
    if creds:
        token = creds.credentials
    elif "authorization" in request.headers:
        token = request.headers["authorization"].removeprefix("Bearer ").strip()
    if not token:
        raise AuthError("missing bearer token")
    claims = verify_jwt(token)
    return Principal(
        user_id=claims["sub"],
        org_id=claims["org_id"],
        email=claims.get("email", ""),
        role=claims.get("role", "viewer"),
    )


async def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    principal.require_role("admin")
    return principal


async def require_internal_secret(x_sync_secret: str = Header(default="")) -> None:
    configured = settings.INTERNAL_SYNC_SECRET
    if not configured:
        # fail closed: the internal endpoint is disabled until a secret is set
        raise AuthError("internal sync endpoint is not configured")
    if not hmac.compare_digest(x_sync_secret, configured):
        raise AuthError("invalid X-Sync-Secret")
