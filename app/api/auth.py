"""Account creation / login (FR-01, AC-01)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_account
from app.config import get_settings
from app.database.database import get_db
from app.database.models import Account, AuthToken
from app.security import hash_password, login_limiter, new_session_token, sha256_hex, verify_password

router = APIRouter(prefix="/v1/auth", tags=["auth"])
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Credentials(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(min_length=8, max_length=256)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL.match(v):
            raise ValueError("invalid email address")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


def _issue_token(db: Session, account: Account) -> TokenResponse:
    ttl = get_settings().auth_token_ttl_hours
    token = new_session_token()
    expires = datetime.now(timezone.utc) + timedelta(hours=ttl)
    db.add(AuthToken(token_hash=sha256_hex(token), account_id=account.account_id, expires_at=expires))
    db.commit()
    return TokenResponse(access_token=token, expires_at=expires)


@router.post("/register", status_code=201)
def register(body: Credentials, db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(Account).where(Account.email == body.email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    account = Account(email=body.email, password_hash=hash_password(body.password))
    db.add(account)
    db.commit()
    return {"account_id": account.account_id, "email": account.email}


@router.post("/login", response_model=TokenResponse)
def login(body: Credentials, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    client = request.client.host if request.client else "unknown"
    if not login_limiter.allow(f"{body.email}|{client}", limit=10):
        raise HTTPException(status_code=429, detail="Too many login attempts; try again shortly")
    account = db.scalar(select(Account).where(Account.email == body.email))
    # Always run a hash verification to keep timing similar for unknown accounts.
    stored = account.password_hash if account else hash_password("x" * 8)
    ok = verify_password(body.password, stored)
    if not account or not ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return _issue_token(db, account)


@router.get("/me")
def me(account: Account = Depends(get_current_account)) -> dict:
    return {"account_id": account.account_id, "email": account.email}


@router.post("/logout", status_code=204)
def logout(
    authorization: str = Header(...),
    _account: Account = Depends(get_current_account),
    db: Session = Depends(get_db),
) -> None:
    row = db.get(AuthToken, sha256_hex(authorization[7:].strip()))
    if row:
        db.delete(row)
        db.commit()
