"""Risk scoring configuration loader (PRD section 17, 33 Maintainability, 35 reproducibility).

Same contract as the detection/anomaly/correlation/threat-intel configs: built-in defaults, `config/risk.yaml`
(path from RISK_CONFIG_PATH, PRD section 41) overrides key by key, and an invalid file never takes the platform
down: it falls back to the defaults and records `status="fallback_defaults"` plus the error (shown in /health).
`fingerprint` is a hash of the effective values so a stored score can be tied to the exact configuration.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import yaml

from app.detection.config import _deep_merge, _resolve

log = logging.getLogger("webintelx.risk.config")

FACTORS = ("behavior", "anomaly", "attack_indicators", "authentication", "sensitive_endpoint",
           "correlation", "asset_impact", "threat_intel")
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "enabled": True,
    "weights": {"behavior": 10, "anomaly": 10, "attack_indicators": 20, "authentication": 20, "sensitive_endpoint": 10,
                "correlation": 15, "asset_impact": 10, "threat_intel": 5},
    "levels": {"critical": 85, "high": 65, "medium": 40},
    "anomaly": {"score_floor": 0.5},
    "attack_indicators": {"breadth_bonus": 0.1},
    "authentication": {"default_value": 0.5,
                       "category_values": {"brute_force_indicator": 0.5, "multi_account_auth_failures": 0.6,
                                           "login_success_after_failure_burst": 1.0}},
    "sensitive_endpoint": {"accessed": 0.7, "with_successful_login": 1.0},
    "correlation": {"stage_weight": 0.4, "size_weight": 0.3, "strength_weight": 0.3, "size_saturation_events": 100},
    "asset_impact": {"default_value": 0.2,
                     "path_prefixes": {"/admin": 1.0, "/api/admin": 1.0, "/api/account/payment-methods": 1.0,
                                       "/api/account": 0.7, "/api/login": 0.5, "/login": 0.5, "/api": 0.4}},
    "threat_intel": {"first_evidence": 0.7, "each_additional": 0.15, "count_synthetic": False},
    "confidence": {"weights": {"signal_diversity": 0.4, "finding_confidence": 0.35, "correlation_strength": 0.25},
                   "diversity_saturation": 4, "top_findings": 3, "truncation_penalty": 0.1},
}


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _unit(v: Any) -> bool:
    return _is_num(v) and 0 <= v <= 1


def validate(cfg: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(cfg.get("enabled"), bool):
        errs.append("enabled must be true/false")
    w = cfg.get("weights")
    if not isinstance(w, dict):
        errs.append("weights must be a mapping")
    else:
        for k, v in w.items():
            if k not in FACTORS:
                errs.append(f"weights.{k}: unknown factor")
            elif not _is_num(v) or v < 0:
                errs.append(f"weights.{k} must be a number >= 0")
        if not any(_is_num(v) and v > 0 for v in w.values()):
            errs.append("at least one weight must be > 0")
    lv = cfg.get("levels")
    if not isinstance(lv, dict) or not all(_is_num(lv.get(k)) for k in ("critical", "high", "medium")):
        errs.append("levels.critical / high / medium must be numbers")
    elif not (0 < lv["medium"] < lv["high"] < lv["critical"] <= 100):
        errs.append("levels must satisfy 0 < medium < high < critical <= 100")
    a = cfg.get("anomaly")
    if not isinstance(a, dict) or not _is_num(a.get("score_floor")) or not 0 <= a["score_floor"] < 1:
        errs.append("anomaly.score_floor must be in [0,1)")
    b = cfg.get("attack_indicators")
    if not isinstance(b, dict) or not _unit(b.get("breadth_bonus")):
        errs.append("attack_indicators.breadth_bonus must be in [0,1]")
    au = cfg.get("authentication")
    if not isinstance(au, dict) or not _unit(au.get("default_value")) or not isinstance(au.get("category_values"), dict) \
            or not all(_unit(v) for v in au["category_values"].values()):
        errs.append("authentication.default_value and category_values must be numbers in [0,1]")
    s = cfg.get("sensitive_endpoint")
    if not isinstance(s, dict) or not _unit(s.get("accessed")) or not _unit(s.get("with_successful_login")):
        errs.append("sensitive_endpoint.accessed / with_successful_login must be in [0,1]")
    c = cfg.get("correlation")
    if not isinstance(c, dict) or not all(_is_num(c.get(k)) and c[k] >= 0 for k in ("stage_weight", "size_weight", "strength_weight")) \
            or not _is_num(c.get("size_saturation_events")) or c["size_saturation_events"] <= 0:
        errs.append("correlation weights must be >= 0 and size_saturation_events > 0")
    elif c["stage_weight"] + c["size_weight"] + c["strength_weight"] <= 0:
        errs.append("correlation weights must not all be 0")
    ai = cfg.get("asset_impact")
    if not isinstance(ai, dict) or not _unit(ai.get("default_value")) or not isinstance(ai.get("path_prefixes"), dict) \
            or not all(isinstance(k, str) and k.startswith("/") and _unit(v) for k, v in ai["path_prefixes"].items()):
        errs.append("asset_impact.default_value in [0,1] and path_prefixes (keys start with '/', values in [0,1]) are required")
    t = cfg.get("threat_intel")
    if not isinstance(t, dict) or not _unit(t.get("first_evidence")) or not _unit(t.get("each_additional")) \
            or not isinstance(t.get("count_synthetic"), bool):
        errs.append("threat_intel.first_evidence / each_additional in [0,1] and count_synthetic true/false are required")
    cf = cfg.get("confidence")
    if not isinstance(cf, dict) or not isinstance(cf.get("weights"), dict) \
            or not all(_is_num(cf["weights"].get(k)) and cf["weights"][k] >= 0 for k in ("signal_diversity", "finding_confidence", "correlation_strength")) \
            or sum(cf["weights"].get(k, 0) for k in ("signal_diversity", "finding_confidence", "correlation_strength")) <= 0:
        errs.append("confidence.weights (signal_diversity, finding_confidence, correlation_strength) must be numbers >= 0, not all 0")
    elif not _is_num(cf.get("diversity_saturation")) or cf["diversity_saturation"] < 1 \
            or not _is_num(cf.get("top_findings")) or cf["top_findings"] < 1 or not _unit(cf.get("truncation_penalty")):
        errs.append("confidence.diversity_saturation >= 1, top_findings >= 1, truncation_penalty in [0,1] are required")
    return errs


def _fingerprint(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:12]


@dataclass(frozen=True)
class RiskConfig:
    data: dict[str, Any]
    status: str = "ok"                       # ok | fallback_defaults
    error: str | None = None
    source: str = "defaults"

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.data)

    def public(self) -> dict[str, Any]:
        return {**copy.deepcopy(self.data), "status": self.status, "error": self.error, "fingerprint": self.fingerprint}


def defaults() -> RiskConfig:
    return RiskConfig(data=copy.deepcopy(DEFAULTS))


def load_config(path: str | None = None) -> RiskConfig:
    path = path or os.environ.get("RISK_CONFIG_PATH", "config/risk.yaml")
    p = _resolve(path)
    if not p.exists():
        log.warning("risk config %s not found; using built-in defaults", path)
        return RiskConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error="config file not found")
    try:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("top level of the file must be a mapping")
        merged = _deep_merge(DEFAULTS, loaded)
        problems = validate(merged)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return RiskConfig(data=merged, status="ok", source=str(p))
    except (yaml.YAMLError, ValueError, OSError) as exc:
        log.error("invalid risk config %s (%s); using built-in defaults", p, exc)
        return RiskConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error=str(exc)[:300])


@lru_cache
def get_risk_config() -> RiskConfig:
    return load_config()
