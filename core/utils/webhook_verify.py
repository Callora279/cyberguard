"""Constant-time verification of inbound SCM webhook signatures.

Both helpers return ``False`` on any missing/empty/malformed input and never
raise, so callers can map a falsy result straight to a 401.
"""
from __future__ import annotations

import hashlib
import hmac


def verify_github(body: bytes, header_sig: str, secret: str) -> bool:
    """Check GitHub's ``X-Hub-Signature-256`` (``sha256=<hex HMAC of body>``)."""
    try:
        if not body or not header_sig or not secret:
            return False
        if not header_sig.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected.encode(), header_sig.encode())
    except Exception:  # noqa: BLE001 - never leak verification errors
        return False


def verify_gitlab(token_header: str, secret: str) -> bool:
    """Check GitLab's ``X-Gitlab-Token`` against the configured shared secret."""
    try:
        if not token_header or not secret:
            return False
        return hmac.compare_digest(token_header.encode(), secret.encode())
    except Exception:  # noqa: BLE001
        return False
