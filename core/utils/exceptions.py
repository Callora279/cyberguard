"""Application exception hierarchy mapped to HTTP responses in main.py."""
from __future__ import annotations


class CyberGuardError(Exception):
    """Base class for all handled errors."""

    status_code = 500
    code = "internal_error"

    def __init__(self, message: str | None = None, *, details: dict | None = None):
        super().__init__(message or self.__doc__ or self.code)
        self.message = message or "internal error"
        self.details = details or {}

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message, "details": self.details}


class AuthError(CyberGuardError):
    """Authentication failed."""

    status_code = 401
    code = "auth_error"


class PermissionError_(CyberGuardError):
    """Caller lacks permission."""

    status_code = 403
    code = "forbidden"


class NotFoundError(CyberGuardError):
    """Resource not found."""

    status_code = 404
    code = "not_found"


class ValidationError(CyberGuardError):
    """Request payload failed validation."""

    status_code = 422
    code = "validation_error"


class RateLimitError(CyberGuardError):
    """Too many requests."""

    status_code = 429
    code = "rate_limited"


class PolicyViolation(CyberGuardError):
    """An AI governance policy blocked the request."""

    status_code = 451
    code = "policy_violation"


class UpstreamError(CyberGuardError):
    """A dependency (Groq, OSV, NVD, ...) failed."""

    status_code = 502
    code = "upstream_error"
