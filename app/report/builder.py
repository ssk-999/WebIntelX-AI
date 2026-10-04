"""Structured incident report (PRD section 24, FR-24, AC-21). PURE: plain dicts in, a plain dict out; no DB, no network, NO LLM.

PRD section 14 lists a "Reporting / Analyst Assistant" as an OPTIONAL MVP role. PRD does not specify how it is built; using the following
implementation assumption: the report is assembled deterministically from stored, already-validated data (so it cannot add claims), and its
executive summary is a template over those numbers. The only AI-authored text in it is the stored investigation hypothesis, which keeps its
`ai_inference` label, evidence references and "not proof" wording (PRD section 19).

Every PRD section 24 item has a key: incident_id, detection_time, affected_resources, source_information, attack_hypothesis, timeline,
attack_graph_summary, supporting_evidence, threat_intelligence, risk, mitre_attack, recommended_response, evidence_limitations, analyst_decision.
Untrusted text (request paths, third-party summaries, analyst comments) is returned as plain text; `render.py` escapes it for Markdown / HTML.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

REPORT_VERSION = 1
TIMELINE_MAX = 200
AUDIT_MAX = 20
IDS_PER_ITEM = 10

DISCLAIMERS = [
    "Observed facts and derived metrics are recorded or deterministically calculated. AI inference is labelled, cites evidence and is not proof of an attack.",
    "Risk level and score come from documented, configuration-driven scoring; confidence reflects evidence quality. Neither is a probability.",
    "Absence of threat-intelligence evidence is neither a claim of safety nor of maliciousness.",
    "Recommendations are proposals that need human approval. This platform executed no response action.",
]


def _iso(v: Any) -> str | None:
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()
    return str(v) if v else None


def _cap(ids: Any, n: int = IDS_PER_ITEM) -> list[str]:
    return [str(i) for i in list(ids or [])[:n]]


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _timeline_rows(timeline: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    rows = [{"timestamp": _iso(e.get("timestamp")), "evidence_type": e.get("evidence_type"), "label": _s(e.get("label")),
             "event_count": e.get("event_count"), "event_ids": _cap(e.get("event_ids")), "entry_id": e.get("entry_id")} for e in timeline[:TIMELINE_MAX]]
    return rows, len(timeline) > TIMELINE_MAX


def _graph_summary(graph: Mapping[str, Any] | None) -> dict[str, Any]:
    g = graph or {}
    nodes, edges = list(g.get("nodes") or []), list(g.get("edges") or [])
    by_type = Counter(str(n.get("type") or n.get("node_type") or "unknown") for n in nodes)
    by_rel = Counter(str(e.get("relationship_type") or e.get("type") or "unknown") for e in edges)
    path = [_s(n.get("label")) for n in sorted(nodes, key=lambda n: (n.get("layer") if isinstance(n.get("layer"), int) else 99, _s(n.get("id")))) if n.get("label")][:12]
    return {"node_count": int(g.get("node_count") or len(nodes)), "edge_count": int(g.get("edge_count") or len(edges)), "nodes_by_type": dict(by_type),
            "edges_by_relationship": dict(by_rel), "layered_path": path,
            "traceability": "Every graph node and edge lists the event ids it rests on (GET /v1/incidents/{id}/graph).",
            "evidence_type": "derived_presentation_layer"}


def _mitre(ti: Mapping[str, Any] | None) -> dict[str, Any]:
    items = []
    for r in (ti or {}).get("results") or []:
        if r.get("indicator_type") == "attack_technique" and r.get("status") == "evidence_found":
            d = r.get("data") or {}
            items.append({"technique_id": d.get("technique_id") or r.get("indicator"), "name": d.get("name"), "tactics": list(d.get("tactics") or []), "url": d.get("url")})
    return {"techniques": items, "note": "MITRE ATT&CK is a mapping/context layer, not proof of compromise." if items
            else "No MITRE ATT&CK technique mapping is available for this incident (none attached to its findings, or threat-intelligence enrichment was not run)."}


def _threat_intel(ti: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(ti, Mapping):
        return {"status": "not_run", "results": [], "notes": ["Threat-intelligence enrichment has not been run for this incident. No threat-intelligence evidence was found or is available."]}
    results = [{"indicator_type": r.get("indicator_type"), "indicator": _s(r.get("indicator")), "provider": r.get("provider"), "status": r.get("status"),
                "evidence_status": r.get("evidence_status"), "summary": _s(r.get("summary")), "synthetic": bool(r.get("synthetic")), "retrieved_at": r.get("retrieved_at")}
               for r in (ti.get("results") or []) if r.get("indicator_type") != "attack_technique"]
    notes = list(ti.get("notes") or [])
    if not any(r["evidence_status"] == "evidence_found" for r in results):
        notes.append("No threat-intelligence evidence was found for the checked indicators. This is not a claim of safety or of maliciousness.")
    return {"status": ti.get("status"), "retrieved_at": ti.get("retrieved_at"), "indicators_checked": ti.get("indicators_checked"), "counts": dict(ti.get("counts") or {}),
            "contains_synthetic_data": bool(ti.get("contains_synthetic")), "results": results, "notes": notes, "disclaimers": list(ti.get("disclaimers") or [])}


def _risk(risk: Mapping[str, Any] | None, inc: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(risk, Mapping) or not risk.get("risk_level"):
        return {"status": "not_scored", "risk_level": inc.get("risk_level"), "risk_score": inc.get("risk_score"), "confidence": inc.get("confidence"), "factors": [],
                "note": "Risk has not been scored for this incident."}
    return {"status": risk.get("status", "ok"), "risk_level": risk.get("risk_level"), "risk_score": risk.get("risk_score"), "confidence": risk.get("confidence"),
            "scored_at": risk.get("scored_at"), "config_fingerprint": (risk.get("config") or {}).get("fingerprint"),
            "factors": [{"factor": f.get("factor"), "label": f.get("label"), "status": f.get("status"), "weight": f.get("weight"), "value": f.get("value"),
                         "points": f.get("points"), "basis": _s(f.get("basis"))} for f in risk.get("factors") or []],
            "formula": risk.get("formula"), "note": "Risk reflects the structured severity calculation; confidence reflects evidence quality. Neither is a probability."}


def _hypothesis(inv: Mapping[str, Any] | None, stale_reasons: Sequence[str]) -> dict[str, Any]:
    if not isinstance(inv, Mapping) or inv.get("status") in (None, "not_run"):
        return {"available": False, "status": "not_run", "evidence_type": "ai_inference",
                "note": "The AI investigation has not been run. No hypothesis is stated; see the deterministic facts and risk factors."}
    inf = inv.get("inference") if isinstance(inv.get("inference"), Mapping) else None
    if inv.get("status") != "ok" or not inf:
        return {"available": False, "status": inv.get("status"), "evidence_type": "ai_inference", "error": inv.get("error"),
                "note": "The AI investigation did not produce a validated hypothesis. Facts, risk, threat intelligence and the alert are unaffected."}
    h = inf.get("hypothesis") or {}
    return {"available": True, "status": "ok", "evidence_type": "ai_inference", "ai_generated": True, "statement": _s(h.get("statement")),
            "attack_category": h.get("attack_category"), "confidence": h.get("confidence"), "confidence_basis": h.get("confidence_basis"),
            "refs": list(h.get("refs") or []), "event_ids": _cap(h.get("event_ids")), "model": inv.get("model"), "generated_at": inv.get("generated_at"),
            "alternative_explanations": [_s(a) for a in inf.get("alternative_explanations") or []],
            "stale": bool(stale_reasons), "stale_reasons": list(stale_reasons),
            "note": "AI inference: an interpretation of the evidence, not proof of an attack."}


def _evidence(inv: Mapping[str, Any] | None, risk: Mapping[str, Any] | None) -> dict[str, Any]:
    inf = (inv or {}).get("inference") if isinstance((inv or {}).get("inference"), Mapping) else {}
    return {"facts": [{"evidence_type": f.get("evidence_type"), "text": _s(f.get("text")), "refs": list(f.get("refs") or [])} for f in (inv or {}).get("facts") or []],
            "supporting_findings": [{"finding_id": f.get("finding_id"), "agent_name": f.get("agent_name"), "category": f.get("category"), "rule_id": f.get("rule_id"),
                                     "confidence": f.get("confidence")} for f in (risk or {}).get("supporting_findings") or []],
            "ai_supporting_claims": [{"evidence_type": "ai_inference", "claim": _s(c.get("claim")), "refs": list(c.get("refs") or []), "event_ids": _cap(c.get("event_ids"))}
                                     for c in (inf or {}).get("supporting_evidence") or []]}


def _limitations(d: Mapping[str, Any], risk: Mapping[str, Any] | None, inv: Mapping[str, Any] | None) -> dict[str, Any]:
    inf = (inv or {}).get("inference") if isinstance((inv or {}).get("inference"), Mapping) else {}
    return {"correlation_limitations": [_s(x) for x in d.get("limitations") or []],
            "deterministic_evidence_gaps": [{"gap": g.get("gap"), "text": _s(g.get("text"))} for g in (risk or {}).get("evidence_gaps") or []],
            "ai_missing_evidence": [{"evidence_type": "missing_evidence", "description": _s(m.get("description")), "why_it_matters": _s(m.get("why_it_matters"))}
                                    for m in (inf or {}).get("missing_evidence") or []],
            "context_notes": [_s(x) for x in (inv or {}).get("context_notes") or []],
            "links_truncated": bool(d.get("links_truncated")), "event_ids_truncated": bool(d.get("event_ids_truncated"))}


def _recommended(rec: Mapping[str, Any] | None, decisions: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(rec, Mapping) or rec.get("status") != "ok":
        return {"status": (rec or {}).get("status", "not_run") if isinstance(rec, Mapping) else "not_run", "recommendations": [],
                "note": "No AI recommendations are available. The analyst decides on a response from the evidence, timeline and risk factors."}
    items = []
    for r in rec.get("recommendations") or []:
        d = decisions.get(r.get("action")) if isinstance(decisions, Mapping) else None
        items.append({"action": r.get("action"), "title": _s(r.get("title")), "rationale": _s(r.get("rationale")), "priority": r.get("priority"), "limitations": _s(r.get("limitations")),
                      "refs": list(r.get("refs") or []), "evidence_type": "recommendation", "requires_human_approval": True, "executed": False,
                      "analyst_decision": ({"decision": d.get("decision"), "comment": d.get("comment"), "decided_at": d.get("decided_at")} if isinstance(d, Mapping) else None)})
    return {"status": "ok", "model": rec.get("model"), "recommendations": items, "approval_note": "Recommendations only; each needs analyst review and approval. Nothing was executed."}


def _analyst(feedback: Sequence[Mapping[str, Any]], d: Mapping[str, Any], status: str) -> dict[str, Any]:
    latest = feedback[0] if feedback else None
    return {"status": status, "decision": (latest or {}).get("analyst_decision") if latest else None,
            "comment": (latest or {}).get("comment") if latest else None, "decided_at": _iso((latest or {}).get("created_at")) if latest else None,
            "feedback_history": [{"feedback_id": f.get("feedback_id"), "decision": f.get("analyst_decision"), "comment": f.get("comment"), "at": _iso(f.get("created_at"))} for f in feedback],
            "status_history": [{k: h.get(k) for k in ("at", "from", "to", "actor", "reason", "comment")} for h in (d.get("lifecycle") or {}).get("history") or []],
            "note": "No analyst decision has been recorded yet." if not latest else "Analyst outcome as stored against the incident."}


def _summary(inc: Mapping[str, Any], d: Mapping[str, Any], risk: Mapping[str, Any], ti: Mapping[str, Any], hyp: Mapping[str, Any], analyst: Mapping[str, Any]) -> str:
    stages = list((d.get("stages") or {}).keys())
    parts = [f"Incident {inc.get('incident_id')}: {inc.get('title')}. Status: {inc.get('status')}."]
    if risk.get("risk_level"):
        parts.append(f"Risk {risk['risk_level']} ({risk.get('risk_score')}/100) with evidence confidence {risk.get('confidence')}.")
    else:
        parts.append("Risk has not been scored.")
    parts.append(f"{int(d.get('event_count') or 0)} correlated event(s)" + (f" across {len(stages)} recognised stage(s)." if stages else "."))
    if ti.get("status") == "not_run":
        parts.append("Threat-intelligence enrichment was not run.")
    else:
        found = sum(1 for r in ti.get("results") or [] if r.get("evidence_status") == "evidence_found")
        parts.append(f"Threat intelligence: {ti.get('indicators_checked')} indicator(s) checked, {found} with evidence.")
    parts.append("An AI hypothesis is included (AI inference, not proof)." if hyp.get("available") else "No validated AI hypothesis is included.")
    parts.append(f"Analyst decision: {analyst['decision']}." if analyst.get("decision") else "No analyst decision has been recorded.")
    return " ".join(parts)


def build_report(*, incident: Mapping[str, Any], timeline: Sequence[Mapping[str, Any]], graph: Mapping[str, Any] | None, feedback: Sequence[Mapping[str, Any]],
                 investigation: Mapping[str, Any] | None = None, stale_reasons: Sequence[str] = (), now: datetime | None = None) -> dict[str, Any]:
    """`incident` = {incident_id, website_id, title, status, risk_level, risk_score, confidence, details, created_at}. `investigation` = the stored M8 result
    (or None). Returns the structured report; identical inputs give an identical report apart from `generated_at`."""
    d = dict(incident.get("details") or {})
    risk_d, ti_d, rec_d = d.get("risk"), d.get("threat_intel"), d.get("recommendations")
    inv = investigation if investigation is not None else d.get("investigation")
    ent = d.get("entities") or {}
    tl, tl_trunc = _timeline_rows(timeline)
    risk = _risk(risk_d, incident)
    ti = _threat_intel(ti_d)
    hyp = _hypothesis(inv, stale_reasons)
    analyst = _analyst(feedback, d, str(incident.get("status") or "DETECTED"))
    synthetic = bool((risk_d or {}).get("contains_synthetic_data")) or bool((ti_d or {}).get("contains_synthetic"))
    alert = d.get("alert") if isinstance(d.get("alert"), Mapping) else None
    return {
        "report_version": REPORT_VERSION, "generated_at": _iso(now or datetime.now(timezone.utc)), "generated_by": "deterministic_report_builder (no LLM)",
        "incident_id": incident.get("incident_id"), "website_id": incident.get("website_id"), "title": incident.get("title"), "title_basis": d.get("title_basis"),
        "status": incident.get("status"), "contains_synthetic_data": synthetic,
        "executive_summary": _summary(incident, d, risk, ti, hyp, analyst),
        "detection_time": {"incident_created_at": _iso(incident.get("created_at")), "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen")},
        "affected_resources": [_s(x) for x in d.get("affected_resources") or []],
        "source_information": {"source_ips": [_s(x) for x in ent.get("source_ips") or []][:20], "source_ip_count": len(ent.get("source_ips") or []),
                               "session_count": len(ent.get("session_ids") or []), "account_count": len(ent.get("user_ids") or []),
                               "event_count": int(d.get("event_count") or 0),
                               "note": "Source IPs are shown as stored (see IP_PRIVACY_MODE). Shared IPs (NAT, proxies) can group unrelated users."},
        "attack_hypothesis": hyp,
        "timeline": {"entries": tl, "entry_count": len(timeline), "truncated": tl_trunc,
                     "note": "evidence_type: observed = recorded events; derived_indicator = rule/model output (not proof); ai_inference = AI output (not proof); system = platform action."},
        "attack_graph_summary": _graph_summary(graph),
        "supporting_evidence": _evidence(inv, risk_d),
        "threat_intelligence": ti,
        "risk": risk,
        "mitre_attack": _mitre(ti_d),
        "recommended_response": _recommended(rec_d, d.get("recommendation_decisions") or {}),
        "alert": ({"alert_id": alert.get("alert_id"), "priority": alert.get("priority"), "status": alert.get("status"), "created_at": alert.get("created_at")} if alert else None),
        "evidence_limitations": _limitations(d, risk_d, inv),
        "analyst_decision": analyst,
        "audit_trail": {"entries": [{k: a.get(k) for k in ("at", "action", "actor", "decision", "from", "to", "recommended_action", "executed", "comment")} for a in (d.get("audit") or [])[-AUDIT_MAX:]],
                        "total_entries_stored": len(d.get("audit") or []), "note": "Append-only list kept with the incident (last entries only); not tamper-proof storage."},
        "disclaimers": list(DISCLAIMERS),
    }
