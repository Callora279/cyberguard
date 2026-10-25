"""Authorisation must run before any network call: an unauthorised target
raises NotAuthorizedError and fingerprint() is never invoked."""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core.services.livescan import scanner
from core.services.livescan.authorization import NotAuthorizedError


def test_unauthorized_target_never_touches_network():
    with patch.object(scanner, "assert_authorized", side_effect=NotAuthorizedError("nope")) as auth, \
         patch.object(scanner, "fingerprint", new=AsyncMock()) as fp:
        with pytest.raises(NotAuthorizedError):
            asyncio.run(scanner.scan_target("org-1", "https://not-authorised.example.com"))
        auth.assert_called_once()
        fp.assert_not_called()
        fp.assert_not_awaited()
