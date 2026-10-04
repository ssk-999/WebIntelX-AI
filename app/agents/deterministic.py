"""Agents 1-3 (Detection, Anomaly, Attack) as structured *roles over deterministic output* (PRD section 14, 13).

PRD section 13 allows the first build to combine roles, and the build rules say not to use an LLM for operations ordinary code does
reliably. Detection, anomaly scoring and attack-indicator matching are already done by the rule engine (M3) and the Isolation Forest (M4);
these functions only *summarise* their stored findings into each role's PRD output shape, with `llm_used: False`, so the investigation
record shows which role contributed what. Pure functions over plain dicts.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence


def _is_ml(f: Mapping[str, Any]) -> bool:
    return f.get("agent_name") == "anomaly_model" or f.get("finding_type") == "ml_anomaly"


def _is_attack(f: Mapping[str, Any]) -> bool:
    return f.get("finding_type") == "attack_indicator" or str(f.get("finding_type") or "").startswith("attack")


def _step(agent: str, role: str, indicators: list[dict[str, Any]], *, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"agent": agent, "role": role, "llm_used": False, "status": "ok" if indicators else "no_findings",
            "suspicious": bool(indicators), "indicators": indicators, **(extra or {})}


def _ind(f: Mapping[str, Any]) -> dict[str, Any]:
    ev = f.get("evidence") or {}
    return {"finding_id": f.get("finding_id"), "rule_id": ev.get("rule_id"), "category": ev.get("category") or f.get("finding_type"),
            "confidence": round(float(f.get("confidence") or 0), 3), "event_ids": list(dict.fromkeys([f.get("event_id"), *(ev.get("event_ids") or [])]))[:10]}


def detection_agent(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    inds = [_ind(f) for f in findings if not _is_ml(f) and not _is_attack(f)]
    return _step("detection_agent", "Detection: rule-based behavioural / authentication signals", inds)


def attack_agent(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    inds = [_ind(f) for f in findings if _is_attack(f)]
    cats = sorted({i["category"] for i in inds})
    return _step("attack_agent", "Attack analysis: potential attack categories from request indicators", inds,
                 extra={"potential_categories": cats, "note": "Indicators, not proof; confidence is a configured weight."})


def anomaly_agent(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    inds = []
    for f in findings:
        if _is_ml(f):
            m = (f.get("evidence") or {}).get("derived_metrics") or {}
            inds.append({**_ind(f), "anomaly_score": m.get("anomaly_score"), "notable_deviations": (m.get("deviations") or m.get("notable_deviations") or [])[:5]
                         if isinstance(m.get("deviations") or m.get("notable_deviations") or [], list) else []})
    return _step("anomaly_agent", "Anomaly: Isolation Forest session anomaly + notable deviations", inds)
