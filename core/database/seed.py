"""Seed a demo organisation, admin user and a default AI policy."""
from __future__ import annotations

from sqlalchemy import select

from core.database.db import init_db, session_scope
from core.database.models import AIPolicy, Organisation, User
from core.utils.config import settings
from core.utils.crypto import hash_password

DEMO_EMAIL = "admin@cyberguard.ai"
DEMO_PASSWORD = "cyberguard-demo"


def seed() -> str:
    init_db()
    with session_scope() as db:
        org = db.scalar(select(Organisation).where(Organisation.name == "Demo Org"))
        if not org:
            org = Organisation(
                name="Demo Org", plan="enterprise", chakra_org_id=settings.CHAKRA_ORG_ID
            )
            db.add(org)
            db.flush()
        if not db.scalar(select(User).where(User.email == DEMO_EMAIL)):
            db.add(
                User(
                    org_id=org.id,
                    email=DEMO_EMAIL,
                    password_hash=hash_password(DEMO_PASSWORD),
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
