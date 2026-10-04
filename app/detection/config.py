"""Detection configuration loader (PRD section 33 Maintainability, section 35 reproducibility).

Defaults live here; `config/detection.yaml` (path from DETECTION_CONFIG_PATH) overrides them key by
key. An unreadable/invalid file never takes the platform down: the loader logs the problem, falls
back to the built-in defaults and records `status="fallback_defaults"` plus the error so /health
can show it (PRD: expose failures, not secrets).
"""
from __future__ import annotations

import copy
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("webintelx.detection.config")
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "analysis_window_hours": 24,
    "sensitive_path_prefixes": ["/api/admin", "/admin", "/api/account/payment-methods"],
    "auth_path_prefixes": ["/login", "/api/login", "/auth", "/api/auth"],
    "headless_user_agent_tokens": ["headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright"],
    "automation_user_agent_tokens": ["scrapy", "curl/", "wget/", "python-requests", "python-urllib", "go-http-client", "libwww-perl"],
    "rules": {
        "R-AUTH-001": {"enabled": True, "min_failures": 10, "run_gap_s": 30, "confidence_base": 0.75, "confidence_max": 0.95},
        "R-AUTH-002": {"enabled": True, "min_failures": 10, "min_distinct_users": 5, "run_gap_s": 30, "confidence": 0.8},
        "R-AUTH-003": {"enabled": True, "lookback_s": 600, "confidence": 0.8, "confidence_account_match": 0.9},
        "R-BEH-001": {"enabled": True, "window_s": 10, "min_requests": 30, "confidence": 0.7},
        "R-BEH-002": {"enabled": True, "confidence_one_signal": 0.55, "confidence_multi_signal": 0.75},
        "R-BEH-003": {"enabled": True, "min_page_views": 5, "max_median_gap_s": 3.0, "confidence": 0.5},
        "R-BEH-004": {"enabled": True, "min_distinct_paths": 3, "confidence": 0.45,
                      "paths": ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git", "/robots.txt",
                                "/sitemap.xml", "/api/docs", "/swagger", "/openapi.json"]},
        "R-ATK-001": {"enabled": True, "confidence": 0.7},
        "R-ATK-002": {"enabled": True, "confidence": 0.65},
        "R-ATK-003": {"enabled": True, "confidence": 0.7},
        "R-ATK-004": {"enabled": True, "confidence": 0.7},
        "R-ATK-005": {"enabled": True, "min_categories": 3, "window_s": 600, "confidence": 0.85},
        "R-WAF-001": {"enabled": True, "confidence": 0.6},
    },
}

_LIST_KEYS = ("sensitive_path_prefixes", "auth_path_prefixes", "headless_user_agent_tokens", "automation_user_agent_tokens")


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def validate(cfg: dict) -> list[str]:
    """Return a list of human-readable problems (empty = valid)."""
    errs: list[str] = []
    if not isinstance(cfg.get("analysis_window_hours"), (int, float)) or cfg["analysis_window_hours"] <= 0:
        errs.append("analysis_window_hours must be a positive number")
    for k in _LIST_KEYS:
        if not isinstance(cfg.get(k), list) or not all(isinstance(x, str) for x in cfg[k]):
            errs.append(f"{k} must be a list of strings")
    rules = cfg.get("rules")
    if not isinstance(rules, dict):
        return errs + ["rules must be a mapping"]
    for rid, params in rules.items():
        if not isinstance(params, dict):
            errs.append(f"{rid}: must be a mapping")
            continue
        for pk, pv in params.items():
            if pk == "enabled":
                if not isinstance(pv, bool):
                    errs.append(f"{rid}.enabled must be true/false")
            elif pk == "paths":
                if not isinstance(pv, list) or not all(isinstance(x, str) for x in pv):
                    errs.append(f"{rid}.paths must be a list of strings")
            elif isinstance(pv, bool) or not isinstance(pv, (int, float)):
                errs.append(f"{rid}.{pk} must be a number")
            elif pk.startswith("confidence") and not 0 <= pv <= 1:
                errs.append(f"{rid}.{pk} must be between 0 and 1")
            elif not pk.startswith("confidence") and pv <= 0:
                errs.append(f"{rid}.{pk} must be > 0")
    return errs


@dataclass(frozen=True)
class DetectionConfig:
    data: dict[str, Any]
    status: str = "ok"                       # ok | fallback_defaults
    error: str | None = None
    source: str = "defaults"

    def rule(self, rule_id: str) -> dict[str, Any]:
        return self.data["rules"].get(rule_id, {})

    def enabled(self, rule_id: str) -> bool:
        return bool(self.rule(rule_id).get("enabled", True))

    def __getitem__(self, key: str) -> Any:
        return self.data[key]


def defaults() -> DetectionConfig:
    return DetectionConfig(data=copy.deepcopy(DEFAULTS))


def _resolve(path: str) -> Path:
    p = Path(path)
    if p.is_absolute() or p.exists():
        return p
    return PROJECT_ROOT / p


def load_config(path: str | None = None) -> DetectionConfig:
    path = path or os.environ.get("DETECTION_CONFIG_PATH", "config/detection.yaml")
    p = _resolve(path)
    if not p.exists():
        log.warning("detection config %s not found; using built-in defaults", path)
        return DetectionConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error="config file not found", source="defaults")
    try:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("top level of the file must be a mapping")
        merged = _deep_merge(DEFAULTS, loaded)
        problems = validate(merged)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return DetectionConfig(data=merged, status="ok", source=str(p))
    except (yaml.YAMLError, ValueError, OSError) as exc:
        log.error("invalid detection config %s (%s); using built-in defaults", p, exc)
        return DetectionConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error=str(exc)[:300], source="defaults")


@lru_cache
def get_detection_config() -> DetectionConfig:
    return load_config()
