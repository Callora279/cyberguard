"""Seed a demo organisation, admin user and a default AI policy."""
from __future__ import annotations

import os
import secrets

from sqlalchemy import select

from core.database.db import init_db, session_scope
from core.database.models import AIPolicy, OrgSettings, Organisation, User
from core.utils.config import settings
from core.utils.crypto import hash_password

DEMO_EMAIL = "admin@cyberguard.ai"


def _demo_password() -> str:
    """DEMO_ADMIN_PASSWORD from the env, else a random one printed exactly once."""
    pw = os.getenv("DEMO_ADMIN_PASSWORD")
    if pw:
        return pw
    pw = secrets.token_urlsafe(16)
    print(f"DEMO_ADMIN_PASSWORD not set; generated demo admin password: {pw}")
    return pw


def seed() -> str:
    if settings.ENV == "production":
        raise SystemExit("refusing to seed demo data when ENV=production")
    init_db()
    with session_scope() as db:
        org = db.scalar(select(Organisation).where(Organisation.name == "Demo Org"))
        if not org:
            org = Organisation(
                name="Demo Org", plan="enterprise", chakra_org_id=settings.CHAKRA_ORG_ID
            )
            db.add(org)
            db.flush()
        if not db.get(OrgSettings, org.id):
            db.add(
                OrgSettings(
                    org_id=org.id,
                    onboarding_completed=True,
                    onboarding_step=4,
                    alert_threshold="high",
                )
            )
        if not db.scalar(select(User).where(User.email == DEMO_EMAIL)):
            db.add(
                User(
                    org_id=org.id,
                    email=DEMO_EMAIL,
                    password_hash=hash_password(_demo_password()),
                    role="admin",
                )
            )
        if not db.scalar(select(AIPolicy).where(AIPolicy.org_id == org.id)):
            db.add(
                AIPolicy(
                    org_id=org.id,
                    name="Default Policy",
                    max_tokens=4096,
                    allowed_models=[settings.GROQ_MODEL, "qwen/qwen3.8-27b"],
                    prohibited_patterns=[
                        r"ignore (all|previous) instructions",
                        r"(?i)system prompt",
                        r"BEGIN RSA PRIVATE KEY",
                    ],
                    data_classification_rules={"pii": "block", "secret": "block"},
                )
            )
        return org.id


if __name__ == "__main__":
    print("seeded org:", seed())
