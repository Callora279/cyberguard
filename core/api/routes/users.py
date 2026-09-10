"""User management within an organisation."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import select

from core.api.middleware.auth import Principal, get_principal, require_admin
from core.database.db import session_scope
from core.database.models import User
from core.utils.crypto import hash_password
from core.utils.exceptions import NotFoundError, ValidationError

router = APIRouter()


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool


class CreateUserIn(BaseModel):
    email: EmailStr
    password: str
    role: str = "analyst"


class UpdateUserIn(BaseModel):
    role: str | None = None
    is_active: bool | None = None


@router.get("/me", response_model=UserOut)
def me(principal: Principal = Depends(get_principal)) -> UserOut:
    with session_scope() as db:
        u = db.get(User, principal.user_id)
        if not u:
            raise NotFoundError("user")
        return UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active)


@router.get("", response_model=list[UserOut])
def list_users(principal: Principal = Depends(get_principal)) -> list[UserOut]:
    with session_scope() as db:
        rows = db.scalars(select(User).where(User.org_id == principal.org_id)).all()
        return [UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active) for u in rows]


@router.post("", response_model=UserOut)
def create_user(body: CreateUserIn, principal: Principal = Depends(require_admin)) -> UserOut:
    if body.role not in ("admin", "analyst", "viewer"):
        raise ValidationError("invalid role")
    with session_scope() as db:
        if db.scalar(select(User).where(User.email == body.email)):
            raise ValidationError("email already exists")
        u = User(
            org_id=principal.org_id,
            email=body.email,
            password_hash=hash_password(body.password),
            role=body.role,
        )
        db.add(u)
        db.flush()
        return UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active)


@router.put("/{user_id}", response_model=UserOut)
def update_user(user_id: str, body: UpdateUserIn, principal: Principal = Depends(require_admin)) -> UserOut:
    with session_scope() as db:
        u = db.get(User, user_id)
        if not u or u.org_id != principal.org_id:
            raise NotFoundError("user")
        if body.role:
            u.role = body.role
        if body.is_active is not None:
            u.is_active = body.is_active
        return UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active)
