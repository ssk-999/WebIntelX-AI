"""Collector / ingestion schema (PRD section 10 telemetry + section 32 FR-06/FR-07).

Strict validation: unknown fields are rejected so malformed telemetry never silently
enters the pipeline. Each event in a batch is validated independently (partial accept).
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_ATTRIBUTES_BYTES = 8192
MAX_FUTURE_SKEW = timedelta(minutes=10)


class EventType(str, Enum):
    PAGE_VIEW = "page_view"
    INTERACTION = "interaction"
    HTTP_REQUEST = "http_request"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    API_ACCESS = "api_access"
    SENSITIVE_ENDPOINT_ACCESS = "sensitive_endpoint_access"
    APP_ERROR = "app_error"
    WAF_ALERT = "waf_alert"
    SECURITY_DECISION = "security_decision"


class EventSource(str, Enum):
    SDK = "sdk"
    AUTH = "auth"
    API = "api"
    WAF = "waf"
    APP = "app"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_type: EventType
    source: EventSource = EventSource.SDK
    timestamp: datetime | None = None
    session_id: str | None = Field(default=None, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)  # anonymous visitor id or authorized account id
    source_ip: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=1024)
    method: HttpMethod | None = None
    endpoint: str | None = Field(default=None, max_length=2048)
    status_code: int | None = Field(default=None, ge=100, le=599)
    attributes: dict = Field(default_factory=dict)  # page sequence, timing, interaction signals, etc.
    is_synthetic: bool = False

    @field_validator("method", mode="before")
    @classmethod
    def _upper_method(cls, v):
        return v.upper() if isinstance(v, str) else v

    @field_validator("source_ip")
    @classmethod
    def _valid_ip(cls, v):
        if v is None or v == "":
            return None
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4/IPv6 address") from exc

    @field_validator("timestamp")
    @classmethod
    def _valid_ts(cls, v):
        if v is None:
            return v
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        v = v.astimezone(timezone.utc)
        if v > datetime.now(timezone.utc) + MAX_FUTURE_SKEW:
            raise ValueError("timestamp is too far in the future")
        return v

    @field_validator("attributes")
    @classmethod
    def _small_attrs(cls, v):
        try:
            size = len(json.dumps(v, default=str))
        except (TypeError, ValueError) as exc:
            raise ValueError("attributes must be JSON-serialisable") from exc
        if size > MAX_ATTRIBUTES_BYTES:
            raise ValueError(f"attributes exceed {MAX_ATTRIBUTES_BYTES} bytes")
        return v


class IngestRequest(BaseModel):
    """Batch envelope. Events stay as raw dicts here; each is validated individually."""

    model_config = ConfigDict(extra="forbid")
    events: list[dict] = Field(min_length=1)


class RejectedEvent(BaseModel):
    index: int
    errors: list[str]


class IngestResponse(BaseModel):
    accepted: int
    rejected: list[RejectedEvent]
    event_ids: list[str]
