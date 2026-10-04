"""Sensitive data masking / minimisation (PRD section 11, FR-08, guardrails).

Deterministic and testable; no LLM involved. Output of this module is what is safe
to place in `processed_data` and, later, in LLM prompts.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

REDACTED = "[REDACTED]"

# Keys whose values must never be stored or forwarded (matched case-insensitively, as substrings).
SENSITIVE_KEY_PARTS = (
    "password", "passwd", "pwd", "secret", "token", "authorization", "cookie",
    "api_key", "apikey", "api-key", "session_key", "credit", "card_number", "cvv", "ssn",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b")
_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)\s*[=:]\s*[^\s&;,\"']+"
)


def is_sensitive_key(key: str) -> bool:
    k = str(key).lower()
    return any(part in k for part in SENSITIVE_KEY_PARTS)


def mask_text(value: str) -> str:
    """Mask emails, bearer tokens, JWTs, card-like numbers and key=value secrets in free text."""
    value = _JWT_RE.sub(REDACTED, value)
    value = _BEARER_RE.sub("Bearer " + REDACTED, value)
    value = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", value)
    value = _EMAIL_RE.sub("[EMAIL]", value)
    value = _CARD_RE.sub(lambda m: "[NUMBER]" if len(re.sub(r"\D", "", m.group(0))) >= 13 else m.group(0), value)
    return value


def mask_value(value: Any, depth: int = 0) -> Any:
    """Recursively mask a JSON-like structure. Sensitive keys are fully redacted."""
    if depth > 6:
        return REDACTED
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {
            str(k): (REDACTED if is_sensitive_key(k) else mask_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [mask_value(v, depth + 1) for v in value[:200]]
    return value


def redact_secret_keys(value: Any, depth: int = 0) -> Any:
    """Like mask_value but only removes secret-named keys (used for authorised raw_data retention)."""
    if depth > 6:
        return REDACTED
    if isinstance(value, dict):
        return {
            str(k): (REDACTED if is_sensitive_key(k) else redact_secret_keys(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secret_keys(v, depth + 1) for v in value[:200]]
    return value


def mask_endpoint(endpoint: str | None) -> str | None:
    """Keep the path; redact values of sensitive query parameters and mask free text in the rest."""
    if not endpoint:
        return endpoint
    parts = urlsplit(endpoint)
    query = ""
    if parts.query:
        pairs = [
            (k, REDACTED if is_sensitive_key(k) else mask_text(v))
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
        ]
        query = urlencode(pairs, safe="[]")
    path = mask_text(parts.path)
    return path + (f"?{query}" if query else "")


def _hmac(salt: str, value: str) -> str:
    return hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()


def privacy_safe_ip(ip: str | None, mode: str, salt: str) -> str | None:
    """PRD: 'IP address or privacy-safe representation'. Modes: none | truncate | hash."""
    if not ip:
        return None
    if mode == "none":
        return ip
    addr = ipaddress.ip_address(ip)
    if mode == "truncate":
        prefix = 24 if addr.version == 4 else 48
        net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        return str(net)
    if mode == "hash":
        return "iph_" + _hmac(salt, ip)[:16]
    return ip


def pseudonymize_user_id(user_id: str | None, salt: str) -> str | None:
    """If the identifier looks like an email, replace it with a stable pseudonym
    (stable so same-user correlation still works)."""
    if not user_id:
        return user_id
    if _EMAIL_RE.fullmatch(user_id):
        return "usr_" + _hmac(salt, user_id.lower())[:12]
    return mask_text(user_id)
