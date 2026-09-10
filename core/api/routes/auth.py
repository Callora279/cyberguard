"""Authentication: register + login (minimal HS256 JWT)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from pydantic import BaseModel, EmailStr
from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import OrgSettings, Organisation, User
from core.utils.crypto import hash_password, sign_jwt, verify_password
from core.utils.exceptions import AuthError, ValidationError

router = APIRouter()

TRIAL_DAYS = 14
# In production, validate against a licensing service. Here: prefix check only.
_VALID_LICENSE_RE = "CG-"


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    org_name: str = "My Organisation"
    license_key: str | None = None
    start_trial: bool = True


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    org_id: str
    role: str
    plan: str = "trial"
    onboarding_completed: bool = False


def _issue(db, user: User) -> TokenOut:
    token = sign_jwt(
        {"sub": user.id, "org_id": user.org_id, "email": user.email, "role": user.role}
    )
    org = db.get(Organisation, user.org_id)
    st = db.get(OrgSettings, user.org_id)
    return TokenOut(
        access_token=token,
        org_id=user.org_id,
        role=user.role,
        plan=org.plan if org else "trial",
        onboarding_completed=bool(st and st.onboarding_completed),
    )


@router.post("/register", response_model=TokenOut)
def register(body: RegisterIn) -> TokenOut:
    if len(body.password) < 8:
        raise ValidationError("password must be at least 8 characters")

    license_key = (body.license_key or "").strip() or None
    if license_key:
        if not license_key.upper().startswith(_VALID_LICENSE_RE):
            raise ValidationError("invalid license key format (expected CG-XXXX-XXXX)")
        plan, trial_ends = "pro", None
    elif body.start_trial:
        plan, trial_ends = "trial", datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)
    else:
        plan, trial_ends = "free", None

    with session_scope() as db:
        if db.scalar(select(User).where(User.email == body.email)):
            raise ValidationError("email already registered")
        org = Organisation(
            name=body.org_name, plan=plan, license_key=license_key, trial_ends_at=trial_ends
        )
        db.add(org)
        db.flush()
        db.add(OrgSettings(org_id=org.id))
        user = User(
            org_id=org.id,
            email=body.email,
            password_hash=hash_password(body.password),
            role="admin",
        )
        db.add(user)
        db.flush()
        return _issue(db, user)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn) -> TokenOut:
    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == body.email))
        if not user or not verify_password(body.password, user.password_hash):
            raise AuthError("invalid credentials")
        if not user.is_active:
            raise AuthError("account disabled")
        return _issue(db, user)
