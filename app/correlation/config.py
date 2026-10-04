"""Correlation configuration loader (PRD section 33 Maintainability, section 35 reproducibility).

Same contract as the detection/anomaly configs: built-in defaults, `config/correlation.yaml` (path from
CORRELATION_CONFIG_PATH) overrides key by key, an invalid file never takes the platform down - it falls
back to defaults and records `status="fallback_defaults"` plus the error (shown in /health).
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

log = logging.getLogger("webintelx.correlation.config")

RELATIONSHIP_TYPES = ("same_ip", "same_session", "same_user", "same_endpoint", "similar_behavior", "attack_sequence")

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "enabled": True,
    "lookback_hours": 72,
    "max_gap_s": {"same_ip": 900, "same_session": 1800, "same_user": 900, "same_endpoint": 900, "similar_behavior": 900},
    "base_strength": {"same_session": 0.9, "same_user": 0.8, "same_ip": 0.6, "attack_sequence": 0.9,
                      "same_endpoint": 0.4, "similar_behavior": 0.3},
    "merge_types": ["same_ip", "same_session", "same_user", "attack_sequence"],
    "max_links_per_cluster": 3000,
    "max_event_ids_in_details": 2000,
    "incident": {"min_max_finding_confidence": 0.6, "min_distinct_categories": 2},
    "timeline": {"group_gap_s": 30, "max_event_ids_per_entry": 50},
}


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def validate(cfg: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(cfg.get("enabled"), bool):
        errs.append("enabled must be true/false")
    for k in ("lookback_hours", "max_links_per_cluster", "max_event_ids_in_details"):
        if not _is_num(cfg.get(k)) or cfg[k] <= 0:
            errs.append(f"{k} must be a positive number")
    for key, check in (("max_gap_s", lambda v: v > 0), ("base_strength", lambda v: 0 <= v <= 1)):
        m = cfg.get(key)
        if not isinstance(m, dict):
            errs.append(f"{key} must be a mapping")
            continue
        for rel, v in m.items():
            if rel not in RELATIONSHIP_TYPES:
                errs.append(f"{key}.{rel}: unknown relationship type")
            elif not _is_num(v) or not check(v):
                errs.append(f"{key}.{rel} is out of range")
    mt = cfg.get("merge_types")
    if not isinstance(mt, list) or not all(t in RELATIONSHIP_TYPES for t in mt):
        errs.append(f"merge_types must be a list of {list(RELATIONSHIP_TYPES)}")
    inc = cfg.get("incident")
    if not isinstance(inc, dict) or not _is_num(inc.get("min_max_finding_confidence")) \
            or not 0 <= inc["min_max_finding_confidence"] <= 1 \
            or not _is_num(inc.get("min_distinct_categories")) or inc["min_distinct_categories"] < 1:
        errs.append("incident.min_max_finding_confidence (0-1) and incident.min_distinct_categories (>=1) are required")
    tl = cfg.get("timeline")
    if not isinstance(tl, dict) or not all(_is_num(tl.get(k)) and tl[k] > 0 for k in ("group_gap_s", "max_event_ids_per_entry")):
        errs.append("timeline.group_gap_s and timeline.max_event_ids_per_entry must be positive numbers")
    return errs


@dataclass(frozen=True)
class CorrelationConfig:
    data: dict[str, Any]
    status: str = "ok"                       # ok | fallback_defaults
    error: str | None = None
    source: str = "defaults"

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def public(self) -> dict[str, Any]:
        return {**copy.deepcopy(self.data), "status": self.status, "error": self.error}


def defaults() -> CorrelationConfig:
    return CorrelationConfig(data=copy.deepcopy(DEFAULTS))


def load_config(path: str | None = None) -> CorrelationConfig:
    path = path or os.environ.get("CORRELATION_CONFIG_PATH", "config/correlation.yaml")
    p = _resolve(path)
    if not p.exists():
        log.warning("correlation config %s not found; using built-in defaults", path)
        return CorrelationConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error="config file not found")
    try:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("top level of the file must be a mapping")
        merged = _deep_merge(DEFAULTS, loaded)
        problems = validate(merged)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return CorrelationConfig(data=merged, status="ok", source=str(p))
    except (yaml.YAMLError, ValueError, OSError) as exc:
        log.error("invalid correlation config %s (%s); using built-in defaults", p, exc)
        return CorrelationConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error=str(exc)[:300])


@lru_cache
def get_correlation_config() -> CorrelationConfig:
    return load_config()
