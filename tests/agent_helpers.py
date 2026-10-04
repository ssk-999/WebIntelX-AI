"""Helpers for the M8 agent tests: plain-dict fixtures and a scripted fake LLM runner (no network, no CrewAI)."""
from __future__ import annotations

import json
from typing import Any

from app.crew.crew import LLMCallError, LLMResult, LLMUnavailable

SECRET_IP, SECRET_USER, SECRET_SESSION = "203.0.113.77", "victim.user@example.com", "sess-secret-123"


def make_incident(level: str = "HIGH") -> dict[str, Any]:
    return {"incident_id": "inc_test1", "title": "Possible credential abuse from one source", "details": {
        "event_count": 144, "seed_event_count": 139, "event_ids": ["e1", "e2", "e127"], "categories": ["brute_force_indicator"],
        "stages": {"credential_attack": {"event_count": 126, "first_event_id": "e1", "last_event_id": "e126"},
                   "authentication_success": {"event_count": 1, "first_event_id": "e127", "last_event_id": "e127"}},
        "entities": {"source_ips": [SECRET_IP], "session_ids": [SECRET_SESSION, "s2"], "user_ids": [SECRET_USER]},
        "affected_resources": ["/api/admin/export"], "link_counts": {"same_ip": 100},
        "limitations": ["Shared IPs can group unrelated users."], "first_seen": "2026-10-03T10:31:02+00:00", "last_seen": "2026-10-03T10:31:50+00:00",
        "risk": make_risk(level), "threat_intel": None}}


def make_risk(level: str = "HIGH") -> dict[str, Any]:
    return {"status": "ok", "risk_level": level, "risk_score": 81.9, "confidence": 0.6, "scored_at": "2026-10-03T10:40:00+00:00",
            "factors": [{"factor": "authentication", "status": "observed", "weight": 20, "value": 1.0, "points": 20.0, "finding_ids": ["fnd_1"]},
                        {"factor": "threat_intel", "status": "not_assessed", "weight": 5, "value": 0.0, "points": 0.0, "finding_ids": []}],
            "evidence_gaps": [{"gap": "threat_intel_not_run", "text": "Threat-intelligence enrichment has not been run."}],
            "supporting_findings": [{"finding_id": "fnd_1", "category": "brute_force_indicator", "rule_id": "R-AUTH-001", "confidence": 0.8}],
            "inputs": {"stages": ["credential_attack", "authentication_success"]}, "contains_synthetic_data": True}


def make_findings() -> list[dict[str, Any]]:
    return [{"finding_id": "fnd_1", "event_id": "e1", "agent_name": "rule_engine", "finding_type": "auth_anomaly", "confidence": 0.8,
             "evidence": {"rule_id": "R-AUTH-001", "rule_title": "Failed-login burst", "category": "brute_force_indicator",
                          "observed": {"source": SECRET_IP, "failed_login_count": 126, "accounts": [SECRET_USER]},
                          "derived_metrics": {"rate_per_s": 7.0}, "interpretation": {"text": "Consistent with credential guessing.", "basis": "rule_template"},
                          "event_ids": ["e1", "e2"]}},
            {"finding_id": "fnd_2", "event_id": "e126", "agent_name": "anomaly_model", "finding_type": "ml_anomaly", "confidence": 0.7,
             "evidence": {"rule_id": "M-ANOM-001", "category": "session_anomaly", "derived_metrics": {"anomaly_score": 0.74}, "event_ids": ["e126"]}}]


def make_timeline() -> list[dict[str, Any]]:
    return [{"timestamp": "2026-10-03T10:31:02+00:00", "evidence_type": "observed", "label": "126 failed login attempts", "event_count": 126,
             "event_ids": ["e1"], "entry_id": "tl_001"}]


GOOD_INVESTIGATION = {"hypothesis": {"statement": "The activity is consistent with credential abuse followed by a login.", "attack_category": "credential_abuse",
                                     "model_confidence": 0.9, "refs": ["F1", "S:credential_attack"]},
                      "supporting_evidence": [{"claim": "126 failed logins preceded a successful login.", "refs": ["S:credential_attack", "S:authentication_success"]},
                                              {"claim": "A rule flagged a failed-login burst.", "refs": ["F1"]}],
                      "missing_evidence": [{"description": "No independent evidence of account takeover.", "why_it_matters": "Login success alone is not takeover."}],
                      "alternative_explanations": ["A password-manager misconfiguration could cause repeated failures."]}
GOOD_RESPONSE = {"recommendations": [{"action": "force_password_reset_review", "title": "Review the targeted account", "rationale": "A login followed the burst.",
                                      "priority": 1, "refs": ["F1", "S:authentication_success"], "limitations": "Does not show what the session did."},
                                     {"action": "block_source_review", "title": "Review source", "rationale": "Single source drove the burst.", "priority": 2, "refs": ["F1"]}]}


class FakeRunner:
    """Scripted runner: each item is a dict/str (returned as text) or an exception (raised). Records every task spec it was given."""

    def __init__(self, script: list[Any], configured: bool = True):
        self.script, self.configured, self.specs, self.calls = list(script), configured, [], 0

    def model_for(self, model_class: str) -> str:
        return "fake-fast" if model_class == "fast" else "fake-reasoning"

    def run(self, spec, *, model_class: str) -> LLMResult:
        self.calls += 1
        self.specs.append(spec)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return LLMResult(text=item if isinstance(item, str) else json.dumps(item), model=self.model_for(model_class))


__all__ = ["FakeRunner", "LLMCallError", "LLMUnavailable", "make_incident", "make_findings", "make_timeline", "make_risk",
           "GOOD_INVESTIGATION", "GOOD_RESPONSE", "SECRET_IP", "SECRET_USER", "SECRET_SESSION"]
