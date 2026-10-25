"""Crypto helpers: password hashing, token signing, hashing, symmetric secrets."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from core.utils.config import settings

_PBKDF2_ROUNDS = 240_000


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt_hex, digest_hex = encoded.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def sha256_hex(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_jwt(claims: dict[str, Any], ttl: int | None = None) -> str:
    """Minimal HS256 JWT so the project has zero hard auth deps."""
    header = {"alg": settings.JWT_ALG, "typ": "JWT"}
    now = int(time.time())
    body = {**claims, "iat": now, "exp": now + (ttl or settings.JWT_TTL_SECONDS)}
    segments = [
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(body, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode()
    sig = hmac.new(settings.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    segments.append(_b64url(sig))
    return ".".join(segments)


def verify_jwt(token: str) -> dict[str, Any]:
    from core.utils.exceptions import AuthError

    try:
        header_b64, body_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise AuthError("malformed token") from exc
    signing_input = f"{header_b64}.{body_b64}".encode()
    expected = hmac.new(
        settings.JWT_SECRET.encode(), signing_input, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
        raise AuthError("bad signature")
    claims = json.loads(_b64url_decode(body_b64))
    if claims.get("exp", 0) < int(time.time()):
        raise AuthError("token expired")
    return claims


def new_secret(prefix: str = "cg") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def _fernet() -> Fernet:
    """Stretch ``settings.ENCRYPTION_KEY`` (an arbitrary string) into a valid
    32-byte urlsafe-base64 Fernet key, so any env var value works — same
    ergonomics as ``JWT_SECRET``."""
    key_material = hashlib.sha256(settings.ENCRYPTION_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_material))


def encrypt_secret(plaintext: str | None) -> str:
    """Encrypt an at-rest secret (e.g. a client-supplied AI provider API key).

    Returns "" for empty input so callers can store/compare blank values
    without a round-trip through Fernet.
    """
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str | None) -> str:
    """Inverse of :func:`encrypt_secret`. Returns "" if the token is empty,
    unreadable, or was encrypted under a different ``ENCRYPTION_KEY``."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def mask_secret(plaintext: str | None, *, keep: int = 4) -> str:
    """A safe-to-display form: 'sk-…ab12'. Never return the full secret."""
    if not plaintext:
        return ""
    if len(plaintext) <= keep:
        return "…" + plaintext
    return f"{plaintext[:2]}…{plaintext[-keep:]}"
