"""Externalised configuration (PRD NFR: Maintainability / section 41).

All values come from environment variables (optionally via a local .env file).
Secrets are read here but are never logged or returned by any endpoint.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

try:  # python-dotenv is optional at runtime
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

_DEV_SALT = "dev-only-insecure-salt"
VALID_IP_MODES = ("none", "truncate", "hash")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    database_url: str
    privacy_salt: str
    ip_privacy_mode: str
    ingest_rate_limit_per_min: int
    ingest_max_batch_size: int
    auth_token_ttl_hours: int
    trust_forwarded_for: bool
    groq_api_key: str
    llm_provider: str
    llm_model: str
    ti_provider: str
    ti_api_key: str
    nvd_api_key: str
    risk_config_path: str
    public_base_url: str
    enable_demo_loader: bool
    auto_detect_on_ingest: bool
    llm_fast_model: str = "openai/gpt-oss-20b"   # PRD section 27 "fast LLM"; env LLM_FAST_MODEL

    @property
    def llm_configured(self) -> bool:
        return bool(self.groq_api_key)

    @property
    def using_dev_salt(self) -> bool:
        return self.privacy_salt == _DEV_SALT


@lru_cache
def get_settings() -> Settings:
    mode = os.environ.get("IP_PRIVACY_MODE", "none").strip().lower()
    if mode not in VALID_IP_MODES:
        mode = "none"
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///WebIntelXAI.db"),
        privacy_salt=os.environ.get("PRIVACY_SALT") or _DEV_SALT,
        ip_privacy_mode=mode,
        ingest_rate_limit_per_min=_int("INGEST_RATE_LIMIT_PER_MIN", 600),
        ingest_max_batch_size=_int("INGEST_MAX_BATCH_SIZE", 100),
        auth_token_ttl_hours=_int("AUTH_TOKEN_TTL_HOURS", 24),
        trust_forwarded_for=_bool("TRUST_FORWARDED_FOR", False),
        groq_api_key=os.environ.get("GROQ_API_KEY", ""),
        llm_provider=os.environ.get("LLM_PROVIDER", "groq"),
        llm_model=os.environ.get("LLM_MODEL", "openai/gpt-oss-120b"),
        ti_provider=os.environ.get("TI_PROVIDER", ""),
        ti_api_key=os.environ.get("TI_API_KEY", ""),
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        risk_config_path=os.environ.get("RISK_CONFIG_PATH", "config/risk.yaml"),
        public_base_url=os.environ.get("PUBLIC_BASE_URL", "").rstrip("/"),
        enable_demo_loader=_bool("ENABLE_DEMO_LOADER", True),
        auto_detect_on_ingest=_bool("AUTO_DETECT_ON_INGEST", True),
        llm_fast_model=os.environ.get("LLM_FAST_MODEL", "openai/gpt-oss-20b").strip() or "openai/gpt-oss-20b",
    )
