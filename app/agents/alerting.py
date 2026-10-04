"""Incident-level alert (PRD section 20, AC-17) - deterministic; no LLM decides whether an alert exists.

PRD section 20: the high-risk incident view includes title, risk level and score, confidence, supporting evidence, related events,
affected resource and recommended next action. An alert is created when the DETERMINISTIC risk level is in `alerting.levels`.
It is idempotent: re-running updates the same alert and keeps `created_at` / `status` (analyst acknowledgement arrives in M10).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

NO_AI_ACTION = ("Review the incident evidence, timeline and risk factors and decide on a response. AI recommendations are not available "
                "for this incident ({reason}).")


def build_alert(incident: Mapping[str, Any], risk: Mapping[str, Any] | None, recommendations: Sequence[Mapping[str, Any]] | None,
                ai_status: str, cfg: Mapping[str, Any], *, prior: Mapping[str, Any] | None = None, now: datetime | None = None) -> dict[str, Any] | None:
    a = cfg["alerting"]
    if not a["enabled"] or not isinstance(risk, Mapping) or risk.get("risk_level") not in a["levels"]:
        return None
    now_iso = (now or datetime.now(timezone.utc)).isoformat()
    d = incident.get("details") or {}
    top = next(iter(recommendations or []), None)
    if top:
        action = {"action": top["action"], "title": top.get("title"), "rationale": top.get("rationale"), "source": "response_agent (AI, proposal)",
                  "requires_human_approval": True}
    else:
        action = {"action": "investigate_further", "title": "Review the incident", "source": "system_default",
                  "rationale": NO_AI_ACTION.format(reason=ai_status), "requires_human_approval": True}
    support = [{"finding_id": f.get("finding_id"), "category": f.get("category"), "rule_id": f.get("rule_id"), "confidence": f.get("confidence")}
               for f in (risk.get("supporting_findings") or [])[:5]]
    return {
        "alert_id": f"alr_{incident.get('incident_id')}", "incident_id": incident.get("incident_id"),
        "priority": a["priority"][risk["risk_level"]], "title": incident.get("title"),
        "risk_level": risk["risk_level"], "risk_score": risk.get("risk_score"), "confidence": risk.get("confidence"),
        "affected_resources": list(d.get("affected_resources") or [])[:5],
        "related_event_count": int(d.get("event_count") or 0), "supporting_evidence": support,
        "stages": [s for s in (risk.get("inputs") or {}).get("stages", [])],
        "recommended_next_action": action, "ai_status": ai_status,
        "contains_synthetic_data": bool(risk.get("contains_synthetic_data")),
        "status": (prior or {}).get("status", "open"), "created_at": (prior or {}).get("created_at", now_iso), "updated_at": now_iso,
        "basis": "deterministic_risk_threshold",
        "note": "Alert priority comes from the deterministic risk level, not from an LLM. The recommended action is a proposal for a human analyst.",
    }
