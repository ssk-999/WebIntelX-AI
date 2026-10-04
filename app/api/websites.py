"""Website registration, ingestion credentials, verification and event listing
(FR-02/03/05/26/27, AC-02/03/05/22)."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_account, get_owned_website
from app.config import get_settings
from app.database.database import get_db
from app.database.models import Account, Event, IngestionCredential, Website
from app.sdk.snippet import build_snippet
from app.security import KEY_PREFIX, new_ingestion_key, sha256_hex

router = APIRouter(prefix="/v1/websites", tags=["websites"])
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$")


class WebsiteCreate(BaseModel):
    domain: str = Field(max_length=300)
    retain_raw_data: bool = False

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = v.strip().lower()
        if "://" in v:
            v = urlsplit(v).hostname or ""
        v = v.split("/")[0].split(":")[0]
        if not _HOST.match(v):
            raise ValueError("domain must be a valid hostname, e.g. shop.example.com")
        return v


def _site_out(site: Website) -> dict:
    return {
        "website_id": site.website_id,
        "domain": site.domain,
        "status": site.status,
        "allowed_origins": site.allowed_origins,
        "retain_raw_data": site.retain_raw_data,
        "created_at": site.created_at,
        "updated_at": site.updated_at,
    }


def _cred_out(c: IngestionCredential) -> dict:
    return {
        "credential_id": c.credential_id,
        "website_id": c.website_id,
        "key_prefix": c.key_prefix,
        "status": c.status,
        "created_at": c.created_at,
        "rotated_at": c.rotated_at,
        "revoked_at": c.revoked_at,
    }


def _base_url(request: Request) -> str:
    return get_settings().public_base_url or str(request.base_url).rstrip("/")


def _create_credential(db: Session, site: Website) -> tuple[IngestionCredential, str]:
    key = new_ingestion_key()
    cred = IngestionCredential(website_id=site.website_id, key_hash=sha256_hex(key), key_prefix=key[: len(KEY_PREFIX) + 4])
    db.add(cred)
    return cred, key


@router.post("", status_code=201)
def create_website(body: WebsiteCreate, request: Request, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    site = Website(account_id=account.account_id, domain=body.domain, retain_raw_data=body.retain_raw_data, allowed_origins=[body.domain])
    db.add(site)
    db.flush()
    cred, key = _create_credential(db, site)
    db.commit()
    return {
        "website": _site_out(site),
        "credential": _cred_out(cred),
        "ingestion_key": key,
        "ingestion_key_note": "Shown once. It is a limited-scope ingestion identifier, not a high-privilege secret.",
        "sdk_snippet": build_snippet(_base_url(request), key),
    }


@router.get("")
def list_websites(account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(Website).where(Website.account_id == account.account_id).order_by(Website.created_at)).all()
    return [_site_out(s) for s in rows]


@router.get("/{website_id}")
def get_website(site: Website = Depends(get_owned_website)) -> dict:
    return _site_out(site)


@router.get("/{website_id}/credentials")
def list_credentials(site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(
        select(IngestionCredential).where(IngestionCredential.website_id == site.website_id).order_by(IngestionCredential.created_at)
    ).all()
    return [_cred_out(c) for c in rows]


@router.post("/{website_id}/credentials/rotate", status_code=201)
def rotate_credential(request: Request, site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    """PRD does not specify a grace period; using immediate cut-off of previous active keys."""
    now = datetime.now(timezone.utc)
    for c in db.scalars(
        select(IngestionCredential).where(IngestionCredential.website_id == site.website_id, IngestionCredential.status == "active")
    ):
        c.status = "rotated"
        c.rotated_at = now
    cred, key = _create_credential(db, site)
    db.commit()
    return {"credential": _cred_out(cred), "ingestion_key": key, "ingestion_key_note": "Shown once.",
            "sdk_snippet": build_snippet(_base_url(request), key)}


@router.post("/{website_id}/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: str, site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    cred = db.scalar(
        select(IngestionCredential).where(
            IngestionCredential.credential_id == credential_id, IngestionCredential.website_id == site.website_id
        )
    )
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    if cred.status != "revoked":
        cred.status = "revoked"
        cred.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return _cred_out(cred)


@router.get("/{website_id}/sdk-snippet")
def sdk_snippet(request: Request, site: Website = Depends(get_owned_website)) -> dict:
    """FR-04. The key is never retrievable after creation, so a placeholder is used; the
    create/rotate responses return the snippet with the real key."""
    return {
        "website_id": site.website_id,
        "snippet": build_snippet(_base_url(request)),
        "instructions": [
            "Paste the snippet just before </head> on every page you want monitored.",
            "Replace YOUR_INGESTION_KEY with the key shown when the website was created or the credential was rotated.",
            "Load a page, then call GET /v1/websites/{id}/verification (dashboard: Verify installation).",
        ],
    }


@router.get("/{website_id}/verification")
def verification(site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    """AC-05: telemetry is 'active' once at least one valid event has arrived."""
    count, last = db.execute(
        select(func.count(Event.event_id), func.max(Event.received_at)).where(Event.website_id == site.website_id)
    ).one()
    return {
        "website_id": site.website_id,
        "status": "active" if count else "waiting_for_telemetry",
        "events_received": count,
        "last_event_received_at": last,
    }


@router.get("/{website_id}/events")
def list_events(
    site: Website = Depends(get_owned_website),
    db: Session = Depends(get_db),
    session_id: str | None = None,
    event_type: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    q = select(Event).where(Event.website_id == site.website_id)
    if session_id:
        q = q.where(Event.session_id == session_id)
    if event_type:
        q = q.where(Event.event_type == event_type)
    rows = db.scalars(q.order_by(Event.timestamp.desc(), Event.event_id).limit(limit).offset(offset)).all()
    # raw_data is intentionally never returned by the API.
    return [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "source": e.source,
            "is_synthetic": e.is_synthetic,
            "session_id": e.session_id,
            "user_id": e.user_id,
            "source_ip": e.source_ip,
            "method": e.method,
            "endpoint": e.endpoint,
            "status_code": e.status_code,
            "processed_data": e.processed_data,
        }
        for e in rows
    ]
