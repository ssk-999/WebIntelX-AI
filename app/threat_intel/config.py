"""Threat-intelligence configuration loader (PRD section 16, 33 Maintainability, 35 reproducibility).

Same contract as the detection/anomaly/correlation configs: built-in defaults, `config/threat_intel.yaml`
(path from THREAT_INTEL_CONFIG_PATH) overrides key by key, and an invalid file never takes the platform
down: it falls back to the defaults and records `status="fallback_defaults"` plus the error (shown in /health).

Which reputation provider is used is NOT configured here: PRD section 41 names TI_PROVIDER / TI_API_KEY as
environment variables, so those stay the single source of truth for the provider and its credential.
"""
from __future__ import annotations

import copy
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import yaml

from app.detection.config import _deep_merge, _resolve

log = logging.getLogger("webintelx.threat_intel.config")

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "enabled": True,
    "cache_ttl_s": 3600,
    "deadline_s": 30,
    "mitre": {"enabled": True},
    "nvd": {"enabled": True, "timeout_s": 8, "rate_limit_per_30s_without_key": 5, "rate_limit_per_30s_with_key": 50},
    "otx": {"timeout_s": 8},
    "indicators": {
        "max_per_incident": 10,
        "ips": {"enabled": True, "query_non_public": False},
        "cves": {"enabled": True},
        "domains": {"enabled": False},
    },
}


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_pos_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def validate(cfg: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(cfg.get("enabled"), bool):
        errs.append("enabled must be true/false")
    if not _is_num(cfg.get("cache_ttl_s")) or cfg["cache_ttl_s"] < 0:
        errs.append("cache_ttl_s must be a number >= 0")
    if not _is_num(cfg.get("deadline_s")) or cfg["deadline_s"] <= 0:
        errs.append("deadline_s must be a positive number")
    for sect in ("mitre", "nvd", "otx", "indicators"):
        if not isinstance(cfg.get(sect), dict):
            errs.append(f"{sect} must be a mapping")
    if errs:
        return errs
    if not isinstance(cfg["mitre"].get("enabled"), bool):
        errs.append("mitre.enabled must be true/false")
    if not isinstance(cfg["nvd"].get("enabled"), bool):
        errs.append("nvd.enabled must be true/false")
    for path, sect, key in (("nvd.timeout_s", "nvd", "timeout_s"), ("otx.timeout_s", "otx", "timeout_s")):
        if not _is_num(cfg[sect].get(key)) or cfg[sect][key] <= 0:
            errs.append(f"{path} must be a positive number")
    for key in ("rate_limit_per_30s_without_key", "rate_limit_per_30s_with_key"):
        if not _is_pos_int(cfg["nvd"].get(key)):
            errs.append(f"nvd.{key} must be a positive integer")
    ind = cfg["indicators"]
    if not _is_pos_int(ind.get("max_per_incident")):
        errs.append("indicators.max_per_incident must be a positive integer")
    for kind, flags in (("ips", ("enabled", "query_non_public")), ("cves", ("enabled",)), ("domains", ("enabled",))):
        sect = ind.get(kind)
        if not isinstance(sect, dict) or not all(isinstance(sect.get(f), bool) for f in flags):
            errs.append(f"indicators.{kind}.{'/'.join(flags)} must be true/false")
    return errs


@dataclass(frozen=True)
class ThreatIntelConfig:
    data: dict[str, Any]
    status: str = "ok"                       # ok | fallback_defaults
    error: str | None = None
    source: str = "defaults"

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def public(self) -> dict[str, Any]:
        """Non-secret; safe to return from the API."""
        return {**copy.deepcopy(self.data), "status": self.status, "error": self.error}


def defaults() -> ThreatIntelConfig:
    return ThreatIntelConfig(data=copy.deepcopy(DEFAULTS))


def load_config(path: str | None = None) -> ThreatIntelConfig:
    path = path or os.environ.get("THREAT_INTEL_CONFIG_PATH", "config/threat_intel.yaml")
    p = _resolve(path)
    if not p.exists():
        log.warning("threat-intel config %s not found; using built-in defaults", path)
        return ThreatIntelConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error="config file not found")
    try:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("top level of the file must be a mapping")
        merged = _deep_merge(DEFAULTS, loaded)
        problems = validate(merged)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return ThreatIntelConfig(data=merged, status="ok", source=str(p))
    except (yaml.YAMLError, ValueError, OSError) as exc:
        log.error("invalid threat-intel config %s (%s); using built-in defaults", p, exc)
        return ThreatIntelConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error=str(exc)[:300])


@lru_cache
def get_ti_config() -> ThreatIntelConfig:
    return load_config()
