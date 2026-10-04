"""Agent / orchestration configuration loader (PRD sections 13, 14, 27, 35, 41).

Same contract as the other config loaders: built-in defaults, `config/agents.yaml` (path from AGENTS_CONFIG_PATH)
overrides key by key, and an invalid file never takes the platform down: it falls back to the defaults and records
`status="fallback_defaults"` plus the error (shown in /health). Model names are NOT here: they come from the
environment (LLM_MODEL / LLM_FAST_MODEL) because PRD section 26 requires them to stay configurable.
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

log = logging.getLogger("webintelx.agents.config")

MODEL_CLASSES = ("reasoning", "fast")
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTIONS = ("investigate_further", "review_affected_accounts", "force_password_reset_review", "require_mfa_review",
           "review_active_sessions", "rate_limit_source_review", "block_source_review", "waf_rule_review", "monitor",
           "notify_security_team")

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "enabled": True,
    "llm": {"temperature": 0.1, "max_output_tokens": 1800, "timeout_s": 60, "max_attempts": 2},
    "context": {"max_chars": 9000, "max_findings": 8, "max_timeline_entries": 12, "max_ti_results": 6,
                "max_event_ids_per_ref": 10, "string_max_len": 80},
    "investigation": {"model_class": "reasoning", "max_supporting_claims": 6, "max_missing_evidence": 5, "max_alternatives": 3},
    "response": {"model_class": "reasoning", "max_recommendations": 5, "allowed_actions": list(ACTIONS)},
    "alerting": {"enabled": True, "levels": ["HIGH", "CRITICAL"], "priority": {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}},
    "orchestration": {"run_anomaly": True, "run_threat_intel": True, "run_risk": True, "max_incidents_per_batch": 3, "audit_max_entries": 50},
    "guardrails": {"overconfident_phrases": ["definitely", "certainly", "undoubtedly", "proves that", "proof of", "confirmed breach",
                                             "confirmed attack", "is a confirmed", "without doubt"]},
}


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _posint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def validate(cfg: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(cfg.get("enabled"), bool):
        errs.append("enabled must be true/false")
    llm = cfg.get("llm")
    if not isinstance(llm, dict) or not _num(llm.get("temperature")) or not 0 <= llm["temperature"] <= 2:
        errs.append("llm.temperature must be in [0,2]")
    elif not _posint(llm.get("max_output_tokens")) or not _num(llm.get("timeout_s")) or llm["timeout_s"] <= 0 \
            or not _posint(llm.get("max_attempts")) or llm["max_attempts"] > 3:
        errs.append("llm.max_output_tokens >= 1, llm.timeout_s > 0, llm.max_attempts in 1..3 are required")
    ctx = cfg.get("context")
    if not isinstance(ctx, dict) or not all(_posint(ctx.get(k)) for k in
                                             ("max_chars", "max_findings", "max_timeline_entries", "max_ti_results", "max_event_ids_per_ref", "string_max_len")):
        errs.append("context.* limits must be integers >= 1")
    elif ctx["max_chars"] < 1000:
        errs.append("context.max_chars must be >= 1000")
    inv = cfg.get("investigation")
    if not isinstance(inv, dict) or inv.get("model_class") not in MODEL_CLASSES \
            or not all(_posint(inv.get(k)) for k in ("max_supporting_claims", "max_missing_evidence", "max_alternatives")):
        errs.append("investigation.model_class must be reasoning|fast and its max_* limits integers >= 1")
    rsp = cfg.get("response")
    if not isinstance(rsp, dict) or rsp.get("model_class") not in MODEL_CLASSES or not _posint(rsp.get("max_recommendations")):
        errs.append("response.model_class must be reasoning|fast and response.max_recommendations an integer >= 1")
    elif not isinstance(rsp.get("allowed_actions"), list) or not rsp["allowed_actions"] \
            or not all(isinstance(a, str) and a in ACTIONS for a in rsp["allowed_actions"]):
        errs.append(f"response.allowed_actions must be a non-empty list drawn from {list(ACTIONS)}")
    al = cfg.get("alerting")
    if not isinstance(al, dict) or not isinstance(al.get("enabled"), bool) or not isinstance(al.get("levels"), list) \
            or not all(x in LEVELS for x in al["levels"]) or not isinstance(al.get("priority"), dict) \
            or not all(al["priority"].get(l) for l in LEVELS):
        errs.append("alerting.enabled true/false, alerting.levels from LOW..CRITICAL and a priority for every level are required")
    o = cfg.get("orchestration")
    if not isinstance(o, dict) or not all(isinstance(o.get(k), bool) for k in ("run_anomaly", "run_threat_intel", "run_risk")) \
            or not _posint(o.get("max_incidents_per_batch")) or not _posint(o.get("audit_max_entries")):
        errs.append("orchestration.run_* must be true/false and max_incidents_per_batch / audit_max_entries integers >= 1")
    g = cfg.get("guardrails")
    if not isinstance(g, dict) or not isinstance(g.get("overconfident_phrases"), list) \
            or not all(isinstance(p, str) and p for p in g["overconfident_phrases"]):
        errs.append("guardrails.overconfident_phrases must be a list of non-empty strings")
    return errs


@dataclass(frozen=True)
class AgentsConfig:
    data: dict[str, Any]
    status: str = "ok"                       # ok | fallback_defaults
    error: str | None = None
    source: str = "defaults"

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.data, sort_keys=True, default=str).encode()).hexdigest()[:12]

    def public(self) -> dict[str, Any]:
        return {**copy.deepcopy(self.data), "status": self.status, "error": self.error, "fingerprint": self.fingerprint}


def defaults() -> AgentsConfig:
    return AgentsConfig(data=copy.deepcopy(DEFAULTS))


def load_config(path: str | None = None) -> AgentsConfig:
    path = path or os.environ.get("AGENTS_CONFIG_PATH", "config/agents.yaml")
    p = _resolve(path)
    if not p.exists():
        log.warning("agents config %s not found; using built-in defaults", path)
        return AgentsConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error="config file not found")
    try:
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("top level of the file must be a mapping")
        merged = _deep_merge(DEFAULTS, loaded)
        problems = validate(merged)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return AgentsConfig(data=merged, status="ok", source=str(p))
    except (yaml.YAMLError, ValueError, OSError) as exc:
        log.error("invalid agents config %s (%s); using built-in defaults", p, exc)
        return AgentsConfig(data=copy.deepcopy(DEFAULTS), status="fallback_defaults", error=str(exc)[:300])


@lru_cache
def get_agents_config() -> AgentsConfig:
    return load_config()
