"""Ingestion pipeline: Validate -> Normalize -> Mask/Minimise -> Feature extraction -> Store.

Sessionisation is derived from stored events on demand (app/pipeline/sessionization.py), so it needs
no extra table. Rules/ML run after storage (app/detection/).
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import ValidationError

from app.config import Settings
from app.database.models import Event, Website, new_id
from app.pipeline import masking
from app.pipeline.features import extract_features
from app.pipeline.normalization import normalize_event
from app.sdk.collector_schema import EventIn


class EventRejected(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _format_errors(exc: ValidationError) -> list[str]:
    out = []
    for e in exc.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "event"
        out.append(f"{loc}: {e['msg']}")
    return out[:10]


def validate(raw: dict) -> EventIn:
    try:
        return EventIn.model_validate(raw)
    except ValidationError as exc:
        raise EventRejected(_format_errors(exc)) from exc


def process_event(
    raw: dict,
    website: Website,
    settings: Settings,
    fallback_ip: str | None = None,
    now: datetime | None = None,
) -> Event:
    """Return an (unsaved) Event row. Raises EventRejected for invalid input."""
    ev = validate(raw)
    norm = normalize_event(ev, now=now)

    # Server-side IP fallback only for SDK events that did not carry one (PRD: source IP
    # "only when collected server-side or otherwise legitimately available").
    if norm["source_ip"] is None and fallback_ip and norm["source"] == "sdk":
        norm["source_ip"] = fallback_ip

    ip_repr = masking.privacy_safe_ip(norm["source_ip"], settings.ip_privacy_mode, settings.privacy_salt)
    user_id = masking.pseudonymize_user_id(norm["user_id"], settings.privacy_salt)
    endpoint = masking.mask_endpoint(norm["endpoint"])
    user_agent = masking.mask_text(norm["user_agent"]) if norm["user_agent"] else None
    attributes = masking.mask_value(norm["attributes"])

    # processed_data is the minimised, masked representation: the only form later
    # eligible for LLM prompts (PRD: raw events must not be sent wholesale to an LLM).
    processed = {
        "event_type": norm["event_type"],
        "source": norm["source"],
        "timestamp": norm["timestamp"].isoformat(),
        "session_id": norm["session_id"],
        "user_id": user_id,
        "source_ip": ip_repr,
        "user_agent": user_agent,
        "method": norm["method"],
        "endpoint": endpoint,
        "status_code": norm["status_code"],
        "attributes": attributes,
    }

    # Features are derived from the MASKED values only (PRD section 11 order: mask -> feature extraction).
    features = extract_features(
        event_type=norm["event_type"], endpoint=endpoint, status_code=norm["status_code"],
        user_agent=user_agent, attributes=attributes, timestamp=norm["timestamp"],
    )

    raw_data = masking.redact_secret_keys(raw) if website.retain_raw_data else None

    return Event(
        event_id=new_id("evt"),   # assigned now (not at flush) so callers can reference it, e.g. demo ground-truth labels
        website_id=website.website_id,
        timestamp=norm["timestamp"],
        received_at=datetime.now(timezone.utc),
        source_ip=ip_repr,
        user_id=user_id,
        session_id=norm["session_id"],
        method=norm["method"],
        endpoint=endpoint,
        status_code=norm["status_code"],
        event_type=norm["event_type"],
        source=norm["source"],
        is_synthetic=norm["is_synthetic"],
        raw_data=raw_data,
        processed_data=processed,
        features=features,
    )
