"""Password hashing, token/key generation and a small in-memory rate limiter.

PRD does not specify the auth mechanism; using stdlib scrypt + opaque bearer tokens
(only hashes are stored). A production deployment would use a managed identity provider.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

KEY_PREFIX = "wix_pk_"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def new_ingestion_key() -> str:
    """Browser-visible, limited-scope ingestion identifier (never a high-privilege secret)."""
    return KEY_PREFIX + secrets.token_urlsafe(24)


class RateLimiter:
    """Sliding-window limiter, per process. Adequate for the single-process MVP."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_s: float = 60.0, cost: int = 1) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_s:
                q.popleft()
            if len(q) + cost > limit:
                return False
            q.extend([now] * cost)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


ingest_limiter = RateLimiter()
login_limiter = RateLimiter()
