"""Shared FastAPI dependencies: authentication and website-scoped authorization (FR-27 / AC-22)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Account, AuthToken, Website
from app.security import sha256_hex


def get_current_account(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Account:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization[7:].strip()
    row = db.get(AuthToken, sha256_hex(token))
    if row is None or row.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    account = db.get(Account, row.account_id)
    if account is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return account


def get_owned_website(
    website_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_db),
) -> Website:
    """404 (not 403) for other customers' websites so existence is not disclosed."""
    site = db.scalar(
        select(Website).where(Website.website_id == website_id, Website.account_id == account.account_id)
    )
    if site is None:
        raise HTTPException(status_code=404, detail="Website not found")
    return site
