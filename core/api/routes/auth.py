"""Authentication: register + login (minimal HS256 JWT)."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, EmailStr
from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Organisation, User
from core.utils.crypto import hash_password, sign_jwt, verify_password
from core.utils.exceptions import AuthError, ValidationError

router = APIRouter()


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    org_name: str = "My Organisation"


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    org_id: str
    role: str


def _issue(user: User) -> TokenOut:
    token = sign_jwt(
        {"sub": user.id, "org_id": user.org_id, "email": user.email, "role": user.role}
    )
    return TokenOut(access_token=token, org_id=user.org_id, role=user.role)


@router.post("/register", response_model=TokenOut)
def register(body: RegisterIn) -> TokenOut:
    if len(body.password) < 8:
        raise ValidationError("password must be at least 8 characters")
    with session_scope() as db:
        if db.scalar(select(User).where(User.email == body.email)):
            raise ValidationError("email already registered")
        org = Organisation(name=body.org_name, plan="free")
        db.add(org)
        db.flush()
        user = User(
            org_id=org.id,
            email=body.email,
            password_hash=hash_password(body.password),
            role="admin",
        )
        db.add(user)
        db.flush()
        return _issue(user)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn) -> TokenOut:
    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == body.email))
        if not user or not verify_password(body.password, user.password_hash):
            raise AuthError("invalid credentials")
        if not user.is_active:
            raise AuthError("account disabled")
        return _issue(user)
