import hashlib
import hmac

from core.utils.webhook_verify import verify_github, verify_gitlab

# Obviously-fake shared secret; not credential-shaped for the secret scanners.
_SECRET = "mock-webhook-secret"
_BODY = b'{"ref": "refs/heads/main", "after": "abc123"}'


def _sign(body: bytes, secret: str = _SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---- GitHub ---------------------------------------------------------------

def test_github_valid_signature():
    assert verify_github(_BODY, _sign(_BODY), _SECRET) is True


def test_github_wrong_secret():
    assert verify_github(_BODY, _sign(_BODY, "other-secret"), _SECRET) is False


def test_github_tampered_body():
    assert verify_github(_BODY + b" ", _sign(_BODY), _SECRET) is False


def test_github_missing_prefix():
    digest = _sign(_BODY).removeprefix("sha256=")
    assert verify_github(_BODY, digest, _SECRET) is False


def test_github_missing_inputs():
    assert verify_github(_BODY, "", _SECRET) is False
    assert verify_github(_BODY, None, _SECRET) is False  # type: ignore[arg-type]
    assert verify_github(_BODY, _sign(_BODY), "") is False
    assert verify_github(b"", _sign(b""), _SECRET) is False


def test_github_garbage_header_does_not_raise():
    assert verify_github(_BODY, "sha256=éé", _SECRET) is False


# ---- GitLab ---------------------------------------------------------------

def test_gitlab_valid_token():
    assert verify_gitlab(_SECRET, _SECRET) is True


def test_gitlab_invalid_token():
    assert verify_gitlab("wrong-token", _SECRET) is False


def test_gitlab_missing_inputs():
    assert verify_gitlab("", _SECRET) is False
    assert verify_gitlab(None, _SECRET) is False  # type: ignore[arg-type]
    assert verify_gitlab(_SECRET, "") is False
    assert verify_gitlab(_SECRET, None) is False  # type: ignore[arg-type]
