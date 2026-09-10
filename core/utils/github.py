"""Fetch a GitHub repository as a source tree for scanning.

Uses the GitHub REST tarball endpoint (no ``git`` binary needed) so the same
code path works in a container. The archive is extracted into a caller-supplied
temp directory and the single top-level directory it contains is returned as the
scan root.
"""
from __future__ import annotations

import re
import tarfile
from pathlib import Path

import httpx

from core.utils.exceptions import UpstreamError, ValidationError
from core.utils.logger import get_logger

logger = get_logger("utils.github")

_REPO_RE = re.compile(r"github\.com[/:]([\w.\-]+)/([\w.\-]+?)(?:\.git)?/?$")


def parse_repo_url(repo_url: str) -> str:
    """``https://github.com/org/repo(.git)`` -> ``org/repo``."""
    m = _REPO_RE.search((repo_url or "").strip())
    if not m:
        raise ValidationError(
            "expected a GitHub repository URL like https://github.com/org/repo"
        )
    return f"{m.group(1)}/{m.group(2)}"


def download_repo(repo: str, token: str | None, dest: Path) -> Path:
    """Download + extract ``org/repo`` into ``dest``; return the scan root."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(headers=headers, timeout=30.0, follow_redirects=True) as c:
            r = c.get(f"https://api.github.com/repos/{repo}/tarball")
            r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403):
            raise UpstreamError(
                "GitHub rejected the token (check scopes: repo / contents:read)"
            ) from exc
        if exc.response.status_code == 404:
            raise ValidationError(
                f"repository '{repo}' not found or not visible to this token"
            ) from exc
        raise UpstreamError(f"GitHub error {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise UpstreamError(f"could not reach GitHub: {exc}") from exc

    archive = dest / "repo.tar.gz"
    archive.write_bytes(r.content)
    with tarfile.open(archive) as tf:
        tf.extractall(dest)  # noqa: S202 - user's own repo, sandboxed tmp dir
    archive.unlink()

    subdirs = [p for p in dest.iterdir() if p.is_dir()]
    return subdirs[0] if len(subdirs) == 1 else dest
