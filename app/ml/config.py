"""Anomaly-model configuration loader (PRD section 33 Maintainability, section 35 reproducibility).

Same contract as `app/detection/config.py`: built-in defaults, `config/anomaly.yaml` (path from
ANOMALY_CONFIG_PATH) overrides key by key, and an unreadable/invalid file never takes the platform down:
the loader falls back to the defaults and records `status="fallback_defaults"` plus the error so /health
and /v1/anomaly/config can show it.
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

log = logging.getLogger("webintelx.ml.config")

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "enabled": True,
    "window_hours": 72,
    "min_training_sessions": 50,
    "model": {"n_estimators": 200, "max_samples": 256, "random_state": 42},
    "score_threshold": 0.65,
    "min_deviation_z": 8.0,
    "notable_feature_z": 3.0,
    "max_notable_features": 5,
    "confidence": {"min": 0.5, "max": 0.9},
}


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def validate(cfg: dict) -> list[str]:
    """Return human-readable problems (empty = valid)."""
    errs: list[str] = []
    if not isinstance(cfg.get("enabled"), bool):
        errs.append("enabled must be true/false")
    for k in ("window_hours", "min_training_sessions", "max_notable_features", "min_deviation_z", "notable_feature_z"):
        if not _is_num(cfg.get(k)) or cfg[k] <= 0:
            errs.append(f"{k} must be a positive number")
    thr = cfg.get("score_threshold")
    if not _is_num(thr) or not 0 < thr < 1:
        errs.append("score_threshold must be between 0 and 1 (exclusive)")
    model = cfg.get("model")
    if not isinstance(model, dict):
        errs.append("model must be a mapping")
    else:
        for k in ("n_estimators", "max_samples"):
            if isinstance(model.get(k), bool) or not isinstance(model.get(k), int) or model[k] < 1:
                errs.append(f"model.{k} must be a positive integer")
        if isinstance(model.get("random_state"), bool) or not isinstance(model.get("random_state"), int):
            errs.append("model.random_state must be an integer")
    conf = cfg.get("confidence")
    if not isinstance(conf, dict) or not all(_is_num(conf.get(k)) and 0 <= conf[k] <= 1 for k in ("min", "max")):
        errs.append("confidence.min and confidence.max must be numbers between 0 and 1")
    elif conf["min"] > conf["max"]:
        errs.append("confidence.min must not exceed confidence.max")
    return errs


@dataclass(frozen=True)
class AnomalyConfig:
    data: dict[str, Any]
    status: str = "ok"                       # ok | fallback_defaults
    error: str | None = None
    source: str = "defaults"

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    @property
    def model(self) -> dict[str, Any]:
        return self.data["model"]

    def public(self) -> dict[str, Any]:
        """Everything here is non-secret and safe to return from the API."""
        return {"status": self.status, "error": self.error, **copy.deepcopy(self.data)}


def defaults() -> AnomalyConfig:
    return AnomalyConfig(data=copy.deepcopy(DEFAULTS))


def load_config(path: str | None = None) -> AnomalyConfig:
    path = path or os.environ.get("ANOMALY_CONFIG_PATH", "config/anomaly.yaml")
    p = _resolve(path)
    if not p.exists():
        log.warning("anomaly config %s not found; using built-in defaults", path)
        return AnomalyConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error="config file not found")
    try:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("top level of the file must be a mapping")
        merged = _deep_merge(DEFAULTS, loaded)
        problems = validate(merged)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return AnomalyConfig(data=merged, status="ok", source=str(p))
    except (yaml.YAMLError, ValueError, OSError) as exc:
        log.error("invalid anomaly config %s (%s); using built-in defaults", p, exc)
        return AnomalyConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error=str(exc)[:300])


@lru_cache
def get_anomaly_config() -> AnomalyConfig:
    return load_config()
