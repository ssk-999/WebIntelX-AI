"""Event ingestion endpoint (FR-06/07, AC-06, credential-security NFR).

Auth: limited-scope ingestion key in `X-WebIntelX-Key`. Checks: key validity/status,
website status, Origin (when a browser sends one), rate limit, per-event validation.
"""
from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.database import get_db
from app.database.models import IngestionCredential, Website
from app.detection.engine import run_detection_for_events
from app.pipeline.pipeline import EventRejected, process_event
from app.sdk.collector_schema import IngestRequest, IngestResponse, RejectedEvent
from app.security import ingest_limiter, sha256_hex

router = APIRouter(tags=["ingestion"])
log = logging.getLogger("webintelx.ingest")


def _client_ip(request: Request, trust_forwarded: bool) -> str | None:
    candidate = None
    if trust_forwarded:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            candidate = xff.split(",")[0].strip()
    if candidate is None and request.client:
        candidate = request.client.host
    try:
        return str(ipaddress.ip_address(candidate)) if candidate else None
    except ValueError:
        return None


def _origin_allowed(origin: str | None, site: Website) -> bool:
    if not origin:  # server-side senders do not send Origin
        return True
    host = urlsplit(origin).hostname
    return bool(host) and host.lower() in {o.lower() for o in (site.allowed_origins or [site.domain])}


@router.post("/v1/ingest", response_model=IngestResponse)
def ingest(
    payload: IngestRequest,
    request: Request,
    x_webintelx_key: str | None = Header(default=None),
    origin: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> IngestResponse:
    settings = get_settings()
    if not x_webintelx_key:
        raise HTTPException(status_code=401, detail="Missing ingestion key")

    cred = db.scalar(select(IngestionCredential).where(IngestionCredential.key_hash == sha256_hex(x_webintelx_key)))
    # One generic error for unknown / rotated / revoked keys so state is not disclosed.
    if cred is None or cred.status != "active":
        raise HTTPException(status_code=401, detail="Invalid ingestion key")
    site = db.get(Website, cred.website_id)
    if site is None or site.status != "active":
        raise HTTPException(status_code=403, detail="Website is not active")
    if not _origin_allowed(origin, site):
        raise HTTPException(status_code=403, detail="Origin not allowed for this website")

    n = len(payload.events)
    if n > settings.ingest_max_batch_size:
        raise HTTPException(status_code=413, detail=f"Batch too large (max {settings.ingest_max_batch_size})")
    if not ingest_limiter.allow(cred.credential_id, settings.ingest_rate_limit_per_min, cost=n):
        raise HTTPException(status_code=429, detail="Ingestion rate limit exceeded")

    fallback_ip = _client_ip(request, settings.trust_forwarded_for)
    rows, rejected = [], []
    for i, raw in enumerate(payload.events):
        try:
            rows.append(process_event(raw, site, settings, fallback_ip=fallback_ip))
        except EventRejected as exc:
            rejected.append(RejectedEvent(index=i, errors=exc.errors))
    if rows:
        db.add_all(rows)
        db.commit()
        if settings.auto_detect_on_ingest:
            # Best effort: detection must never make telemetry ingestion fail (PRD: decouple ingestion/storage
            # from optional processing; SDK must not break the customer's website).
            try:
                run_detection_for_events(db, site.website_id, rows)
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                log.error("auto-detection failed for credential=%s: %s", cred.credential_id, type(exc).__name__)
    if rejected:
        log.info("ingest credential=%s accepted=%d rejected=%d", cred.credential_id, len(rows), len(rejected))
    return IngestResponse(accepted=len(rows), rejected=rejected, event_ids=[r.event_id for r in rows])
