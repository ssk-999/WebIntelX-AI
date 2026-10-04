"""Feature extraction stage (PRD section 11, FR-09).

Pure, deterministic, per-event. Runs AFTER masking, so features are derived from the minimised
representation only. Features are neutral descriptors (no verdicts): attack/anomaly decisions are made
by the rules and, later, the ML model. PRD does not specify the feature list; this is the
implementation assumption (FEATURE_VERSION lets later milestones evolve it safely).

Note: the masker re-encodes query strings, so "encoded character ratio" is intentionally NOT a feature
(it would measure the masker, not the client).
"""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from app.detection.config import DetectionConfig, get_detection_config

FEATURE_VERSION = 1
REQUEST_EVENT_TYPES = frozenset({"page_view", "http_request", "api_access", "sensitive_endpoint_access"})
AUTH_EVENT_TYPES = frozenset({"login_success", "login_failure", "session_created", "session_terminated"})
_SPECIAL_CHARS = frozenset("'\"<>;()\\`{}|")
_INTERACTION_KEYS = ("clicks", "key_events", "scroll_events", "mouse_moves")


def classify_user_agent(ua: str | None, cfg: DetectionConfig) -> str:
    """empty | headless_browser | automation_tool | browser | other (lower-case substring match on configured tokens)."""
    if not ua:
        return "empty"
    low = ua.lower()
    if any(t in low for t in cfg["headless_user_agent_tokens"]):
        return "headless_browser"
    if any(t in low for t in cfg["automation_user_agent_tokens"]):
        return "automation_tool"
    return "browser" if low.startswith("mozilla/") else "other"


def _num(value: Any, lo: int = 0, hi: int = 10**9) -> int | None:
    """Accept only real ints/floats (bools are rejected); clamp to a sane range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(min(max(value, lo), hi))


def _decoded_query(endpoint: str) -> str:
    return unquote_plus(urlsplit(endpoint).query)


def extract_features(
    *,
    event_type: str,
    endpoint: str | None,
    status_code: int | None,
    user_agent: str | None,
    attributes: dict | None,
    timestamp,
    cfg: DetectionConfig | None = None,
) -> dict:
    cfg = cfg or get_detection_config()
    attrs = attributes if isinstance(attributes, dict) else {}
    path = urlsplit(endpoint).path if endpoint else None
    query = _decoded_query(endpoint) if endpoint else ""
    path_l = (path or "").lower()

    interaction_total = None
    if event_type == "interaction":
        parts = [_num(attrs.get(k)) for k in _INTERACTION_KEYS]
        interaction_total = sum(p for p in parts if p is not None)

    wd = attrs.get("webdriver")
    return {
        "v": FEATURE_VERSION,
        "path": path,
        "path_depth": len([s for s in (path or "").split("/") if s]),
        "has_query": bool(query),
        "query_length": len(query),
        "param_count": len(parse_qsl(query, keep_blank_values=True)) if query else 0,
        "special_char_count": sum(1 for c in query if c in _SPECIAL_CHARS),
        "is_request_event": event_type in REQUEST_EVENT_TYPES,
        "is_auth_event": event_type in AUTH_EVENT_TYPES,
        "is_auth_endpoint": any(path_l == p or path_l.startswith(p + "/") for p in cfg["auth_path_prefixes"]),
        "is_sensitive_endpoint": event_type == "sensitive_endpoint_access"
        or any(path_l == p or path_l.startswith(p + "/") for p in cfg["sensitive_path_prefixes"]),
        "status_class": f"{status_code // 100}xx" if status_code else None,
        "is_error_status": bool(status_code and status_code >= 400),
        "ua_class": classify_user_agent(user_agent, cfg),
        "webdriver": wd if isinstance(wd, bool) else None,
        "interaction_total": interaction_total,
        "page_seq": _num(attrs.get("page_seq")) if event_type == "page_view" else None,
        "load_ms": _num(attrs.get("load_ms"), hi=600_000) if event_type == "page_view" else None,
        "hour_utc": timestamp.hour if timestamp is not None else None,
    }
