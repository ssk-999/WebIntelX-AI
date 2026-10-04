"""Database models (PRD section 30).

PRD does not specify the following; using these implementation assumptions:
  * `accounts` / `auth_tokens` tables exist because FR-01 requires login and the
    Websites table needs an "owner/account reference".
  * `websites.allowed_origins` and `websites.retain_raw_data` implement the PRD's
    "restrict origins where practical" and "raw_data where retention is authorized".
  * `events.is_synthetic` / `events.received_at` exist so demo data is clearly
    identifiable (rule 24) and for installation verification (AC-05).
  * `incidents.details` (JSON) will hold the structured incident object later.
  * `correlations.website_id` supports website isolation; `incident_id` is nullable
    because correlations exist before an incident is created.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.database.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class UTCDateTime(TypeDecorator):
    """Store timezone-aware datetimes as UTC; SQLite drops tzinfo so restore it on read."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=timezone.utc)


class Account(Base):
    __tablename__ = "accounts"
    account_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("acc"))
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    websites: Mapped[list["Website"]] = relationship(back_populates="account")


class AuthToken(Base):
    """Session tokens; only the SHA-256 of the token is stored."""

    __tablename__ = "auth_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class Website(Base):
    __tablename__ = "websites"
    website_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("web"))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.account_id"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default="active")
    allowed_origins: Mapped[list] = mapped_column(JSON, default=list)
    retain_raw_data: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    account: Mapped[Account] = relationship(back_populates="websites")
    credentials: Mapped[list["IngestionCredential"]] = relationship(back_populates="website")


class IngestionCredential(Base):
    """Limited-scope browser ingestion identifier. Only a hash is stored; the plaintext
    key is shown once at creation/rotation."""

    __tablename__ = "ingestion_credentials"
    credential_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("cred"))
    website_id: Mapped[str] = mapped_column(ForeignKey("websites.website_id"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | rotated | revoked
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    website: Mapped[Website] = relationship(back_populates="credentials")


class Event(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("evt"))
    website_id: Mapped[str] = mapped_column(ForeignKey("websites.website_id"))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(40))
    source: Mapped[str] = mapped_column(String(20))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    processed_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    features: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_events_site_session", "website_id", "session_id"),
        Index("ix_events_site_time", "website_id", "timestamp"),
        Index("ix_events_site_ip", "website_id", "source_ip"),
    )


class Finding(Base):
    __tablename__ = "findings"
    finding_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("fnd"))
    event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id"), index=True)
    agent_name: Mapped[str] = mapped_column(String(60))
    finding_type: Mapped[str] = mapped_column(String(60))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("inc"))
    website_id: Mapped[str] = mapped_column(ForeignKey("websites.website_id"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="DETECTED")
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Correlation(Base):
    __tablename__ = "correlations"
    correlation_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("cor"))
    website_id: Mapped[str] = mapped_column(ForeignKey("websites.website_id"), index=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.incident_id"), nullable=True, index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id"))
    related_event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id"))
    relationship_type: Mapped[str] = mapped_column(String(40))
    strength: Mapped[float | None] = mapped_column(Float, nullable=True)


class Feedback(Base):
    __tablename__ = "feedback"
    feedback_id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("fb"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id"), index=True)
    analyst_decision: Mapped[str] = mapped_column(String(30))
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
