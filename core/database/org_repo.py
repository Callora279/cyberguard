"""Resolve an organisation's connected GitHub repo (onboarding step 1)."""
from __future__ import annotations

from core.database.db import session_scope
from core.database.models import OrgSettings


def connected_repo(org_id: str) -> tuple[str | None, str | None]:
    """Return (github_repo_url, github_token) configured for this org, or (None, None)."""
    with session_scope() as db:
        row = db.get(OrgSettings, org_id)
        return (row.github_repo_url, row.github_token) if row else (None, None)
