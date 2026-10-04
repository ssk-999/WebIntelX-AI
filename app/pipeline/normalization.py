"""Normalisation stage (PRD section 11): canonical field values for storage and correlation."""
from __future__ import annotations

from datetime import datetime, timezone

from app.sdk.collector_schema import EventIn


def normalize_endpoint(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    endpoint = endpoint.strip()
    # Drop fragment; keep path and query (query is masked later).
    endpoint = endpoint.split("#", 1)[0]
    if not endpoint.startswith("/") and "://" not in endpoint:
        endpoint = "/" + endpoint
    return endpoint


def normalize_event(ev: EventIn, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    return {
        "timestamp": ev.timestamp or now,
        "event_type": ev.event_type.value,
        "source": ev.source.value,
        "session_id": ev.session_id,
        "user_id": ev.user_id,
        "source_ip": ev.source_ip,
        "user_agent": (ev.user_agent or None),
        "method": ev.method.value if ev.method else None,
        "endpoint": normalize_endpoint(ev.endpoint),
        "status_code": ev.status_code,
        "attributes": ev.attributes,
        "is_synthetic": ev.is_synthetic,
    }
