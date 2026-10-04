"""Pure data-shaping helpers for the Streamlit dashboard (PRD section 23). No Streamlit, no network, no database.

Everything here turns API JSON into display structures and is unit-tested without the UI stack
(tests/test_dashboard_viewmodels.py). Two rules are enforced here rather than in the UI:
  * evidence labels keep PRD section 19's separation (observed / derived / AI inference / missing evidence / recommendation);
  * third-party or attacker-controlled text is escaped before it reaches st.markdown (`md_escape`).
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

EVIDENCE_LABELS = {
    "observed": "Observed fact",
    "derived_metric": "Derived metric",
    "derived_indicator": "Derived indicator (rule/model output, not proof)",
    "derived_correlation": "Derived correlation",
    "ai_inference": "AI inference (not proof)",
    "missing_evidence": "Missing evidence",
    "recommendation": "Recommendation (needs human approval)",
    "system": "Platform action",
}
EVIDENCE_COLORS = {
    "observed": "#2b6cb0", "derived_metric": "#6b46c1", "derived_indicator": "#b7791f", "derived_correlation": "#b7791f",
    "ai_inference": "#c53030", "missing_evidence": "#718096", "recommendation": "#2f855a", "system": "#4a5568",
}
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
RISK_COLORS = {"CRITICAL": "#9b2c2c", "HIGH": "#c05621", "MEDIUM": "#b7791f", "LOW": "#2f855a"}
CLOSED_STATUSES = {"RESOLVED", "FALSE_POSITIVE"}
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~$&])")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def md_escape(value: Any, max_len: int = 400) -> str:
    """Make untrusted text display as text: strip control characters, truncate, backslash-escape Markdown/HTML specials."""
    s = _CTRL.sub("", "" if value is None else str(value))
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return _MD_SPECIAL.sub(r"\\\1", s)


def evidence_label(evidence_type: str | None) -> str:
    return EVIDENCE_LABELS.get(evidence_type or "", "Unlabelled")


def short_ids(ids: Sequence[str] | None, n: int = 3) -> str:
    ids = list(ids or [])
    if not ids:
        return "-"
    more = f" (+{len(ids) - n} more)" if len(ids) > n else ""
    return ", ".join(ids[:n]) + more


def risk_sort_key(item: Mapping[str, Any]) -> tuple:
    """Highest risk first; unscored last; newest first as tie-break."""
    score = item.get("risk_score")
    return (score is None, -(score or 0.0), RISK_ORDER.get((item.get("risk_level") or "").upper(), 9))


# ------------------------------------------------------------------ dashboard
def suspicious_event_count(findings: Iterable[Mapping[str, Any]]) -> int:
    """Distinct events that carry a finding or are cited as evidence by one (same definition as the detection engine)."""
    ids: set[str] = set()
    for f in findings:
        if f.get("event_id"):
            ids.add(f["event_id"])
        ev = f.get("evidence") or {}
        for i in ev.get("event_ids") or []:
            ids.add(i)
    return len(ids)


def dashboard_kpis(verification: Mapping[str, Any] | None, findings: Sequence[Mapping[str, Any]] | None,
                   incidents: Sequence[Mapping[str, Any]] | None, alerts: Sequence[Mapping[str, Any]] | None,
                   findings_limit: int | None = None) -> dict[str, Any]:
    """PRD 23 Main Dashboard KPIs. `suspicious_events_is_lower_bound` is true when the findings page was full."""
    findings, incidents, alerts = list(findings or []), list(incidents or []), list(alerts or [])
    active = [i for i in incidents if (i.get("status") or "DETECTED").upper() not in CLOSED_STATUSES]
    high = [i for i in active if (i.get("risk_level") or "").upper() in ("HIGH", "CRITICAL")]
    return {
        "monitoring_status": (verification or {}).get("status", "unknown"),
        "total_events": (verification or {}).get("events_received", 0) or 0,
        "suspicious_events": suspicious_event_count(findings),
        "suspicious_events_is_lower_bound": bool(findings_limit and len(findings) >= findings_limit),
        "active_incidents": len(active),
        "high_risk_incidents": len(high),
        "open_alerts": len([a for a in alerts if (a.get("status") or "open") == "open"]),
    }


def funnel_rows(kpis: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Measured reduction from raw events to the high-risk investigation (PRD 20). Measured values only; the PRD's
    10,000 -> 47 -> 8 -> 3 -> 1 figures are demo targets and are never shown here."""
    return [
        {"stage": "Events ingested", "count": kpis.get("total_events", 0)},
        {"stage": "Suspicious events", "count": kpis.get("suspicious_events", 0)},
        {"stage": "Incidents", "count": kpis.get("active_incidents", 0)},
        {"stage": "High-risk incidents", "count": kpis.get("high_risk_incidents", 0)},
    ]


def incident_cards(incidents: Sequence[Mapping[str, Any]], alerts: Sequence[Mapping[str, Any]] | None = None) -> list[dict[str, Any]]:
    alert_by_inc = {a.get("incident_id"): a for a in (alerts or [])}
    cards = []
    for i in sorted(incidents or [], key=risk_sort_key):
        d = i.get("details") or {}
        a = alert_by_inc.get(i.get("incident_id"))
        cards.append({
            "incident_id": i.get("incident_id"), "title": i.get("title") or "Untitled incident",
            "risk_level": (i.get("risk_level") or "NOT SCORED").upper(), "risk_score": i.get("risk_score"),
            "confidence": i.get("confidence"), "status": i.get("status") or "DETECTED",
            "event_count": d.get("event_count"), "affected_resources": list(d.get("affected_resources") or [])[:3],
            "priority": (a or {}).get("priority"), "has_alert": a is not None,
            "contains_synthetic": bool((a or {}).get("contains_synthetic_data") or (d.get("risk") or {}).get("contains_synthetic_data")),
        })
    return cards


# ------------------------------------------------------------------ investigation page
def risk_factor_rows(risk: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """PRD 17: the UI shows the factors contributing to the score. Sorted by points contributed."""
    rows = [{"factor": f.get("factor"), "status": f.get("status"), "weight": f.get("weight"), "value": f.get("value"),
             "points": f.get("points"), "basis": f.get("basis", ""), "finding_ids": list(f.get("finding_ids") or [])}
            for f in (risk or {}).get("factors") or []]
    return sorted(rows, key=lambda r: -(r["points"] or 0))


def evidence_gap_rows(risk: Mapping[str, Any] | None, investigation: Mapping[str, Any] | None = None) -> list[dict[str, str]]:
    """Deterministic gaps (risk) and AI-identified missing evidence (investigation), kept distinguishable (AC-15)."""
    rows = [{"source": "deterministic", "evidence_type": "missing_evidence", "text": g.get("text") or g.get("gap") or ""}
            for g in (risk or {}).get("evidence_gaps") or []]
    inf = (investigation or {}).get("inference") or {}
    for m in inf.get("missing_evidence") or []:
        text = m.get("description", "")
        if m.get("why_it_matters"):
            text += f" Why it matters: {m['why_it_matters']}"
        rows.append({"source": "ai_agent", "evidence_type": "missing_evidence", "text": text})
    return rows


def timeline_rows(timeline: Sequence[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for t in timeline or []:
        et = t.get("evidence_type")
        ids = list(t.get("event_ids") or [])
        out.append({"entry": t.get("entry_id"), "timestamp": t.get("timestamp"), "label": t.get("label", ""), "evidence_type": et,
                    "evidence_label": evidence_label(et), "color": EVIDENCE_COLORS.get(et or "", "#4a5568"),
                    "event_count": t.get("event_count", len(ids)), "event_ids": ids, "event_ids_short": short_ids(ids),
                    "event_ids_truncated": bool(t.get("event_ids_truncated"))})
    return out


def investigation_view(inv: Mapping[str, Any] | None) -> dict[str, Any]:
    """Splits a stored investigation into facts (code-authored) and inference (model-authored), plus validation counters."""
    inv = inv or {}
    if inv.get("status") in (None, "not_run"):
        return {"available": False, "status": inv.get("status") or "not_run", "error": None, "facts": [], "hypothesis": None,
                "claims": [], "missing_evidence": [], "alternatives": [], "validation": {}, "notes": inv.get("notes") or []}
    inf = inv.get("inference") or {}
    hyp = inf.get("hypothesis")
    return {
        "available": bool(hyp), "status": inv.get("status"), "error": inv.get("error"), "model": inv.get("model"),
        "stale": bool(inv.get("stale")), "stale_reasons": list(inv.get("stale_reasons") or []),
        "facts": [{"evidence_type": f.get("evidence_type"), "label": evidence_label(f.get("evidence_type")), "text": f.get("text", ""),
                   "refs": list(f.get("refs") or [])} for f in inv.get("facts") or []],
        "hypothesis": None if not hyp else {"statement": hyp.get("statement", ""), "category": hyp.get("attack_category"),
                                           "confidence": hyp.get("confidence"), "model_confidence": hyp.get("model_confidence"),
                                           "event_ids": list(hyp.get("event_ids") or []), "refs": list(hyp.get("refs") or []),
                                           "basis": hyp.get("confidence_basis", "")},
        "claims": [{"claim": c.get("claim", ""), "refs": list(c.get("refs") or []), "event_ids": list(c.get("event_ids") or [])}
                   for c in inf.get("supporting_evidence") or []],
        "missing_evidence": [{"description": m.get("description", ""), "why_it_matters": m.get("why_it_matters", "")}
                             for m in inf.get("missing_evidence") or []],
        "alternatives": [str(a) for a in inf.get("alternative_explanations") or []],
        "validation": dict(inf.get("validation") or {}), "disclaimer": inv.get("disclaimer", ""), "notes": inv.get("notes") or [],
    }


def recommendation_rows(rec: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    return [{"priority": r.get("priority"), "action": r.get("action"), "title": r.get("title", ""), "rationale": r.get("rationale", ""),
             "limitations": r.get("limitations", ""), "event_ids": list(r.get("event_ids") or []),
             "requires_human_approval": r.get("requires_human_approval", True), "status": r.get("status", "proposed"),
             "executed": bool(r.get("executed", False))}
            for r in sorted((rec or {}).get("recommendations") or [], key=lambda r: r.get("priority") or 99)]


def ti_rows(report: Mapping[str, Any] | None) -> dict[str, Any]:
    """Threat-intelligence table with the No-Evidence Rule made explicit (PRD 16, AC-11)."""
    report = report or {}
    rows = [{"indicator_type": r.get("indicator_type"), "indicator": r.get("indicator"), "provider": r.get("provider"),
             "status": r.get("status"), "summary": r.get("summary", ""), "source": r.get("source", ""),
             "synthetic": bool(r.get("synthetic")), "limitations": list(r.get("limitations") or [])}
            for r in report.get("results") or []]
    found = [r for r in rows if r["status"] == "evidence_found"]
    return {"status": report.get("status", "not_run"), "rows": rows, "evidence_found": len(found),
            "has_synthetic": any(r["synthetic"] for r in rows), "notes": list(report.get("notes") or []),
            "banner": ("SYNTHETIC DEMO DATA is included below; it does not reflect real reputation." if any(r["synthetic"] for r in rows) else None)
                      or (None if found or not rows else "No threat-intelligence evidence was found. This is neither a sign of safety nor of maliciousness."),
            }


# ------------------------------------------------------------------ attack graph layout
def graph_layout(graph: Mapping[str, Any] | None, x_gap: float = 1.0, y_gap: float = 1.0) -> dict[str, Any]:
    """Deterministic layered layout (x = node `layer`, y = rank inside the layer, centred). Edges that point at unknown nodes are
    dropped. Every node/edge keeps its event_ids so the UI can trace it to evidence (AC-13)."""
    graph = graph or {}
    nodes = list(graph.get("nodes") or [])
    by_layer: dict[int, list[Mapping[str, Any]]] = {}
    for n in nodes:
        by_layer.setdefault(int(n.get("layer", 0)), []).append(n)
    pos: dict[str, tuple[float, float]] = {}
    out_nodes = []
    for layer in sorted(by_layer):
        col = sorted(by_layer[layer], key=lambda n: (str(n.get("type")), str(n.get("timestamp") or ""), str(n.get("id"))))
        for k, n in enumerate(col):
            x, y = layer * x_gap, (k - (len(col) - 1) / 2) * y_gap
            pos[n["id"]] = (x, y)
            out_nodes.append({"id": n["id"], "type": n.get("type"), "label": n.get("label", ""), "x": x, "y": y,
                              "event_count": n.get("event_count", 0), "event_ids": list(n.get("event_ids") or []),
                              "evidence_type": n.get("evidence_type"), "stage_labels": list(n.get("stage_labels") or [])})
    out_edges = []
    for e in graph.get("edges") or []:
        if e.get("source") in pos and e.get("target") in pos:
            (x0, y0), (x1, y1) = pos[e["source"]], pos[e["target"]]
            out_edges.append({"id": e.get("id"), "source": e["source"], "target": e["target"], "relationship": e.get("relationship"),
                              "evidence_type": e.get("evidence_type"), "strength": e.get("strength"), "x0": x0, "y0": y0, "x1": x1, "y1": y1,
                              "event_ids": list(e.get("event_ids") or [])})
    return {"nodes": out_nodes, "edges": out_edges, "dropped_edges": len(graph.get("edges") or []) - len(out_edges)}


def error_banner(kind: str, detail: str | None = None) -> str:
    """User-facing text for degraded states (PRD 33 Observability): never includes secrets."""
    base = {"backend_down": "The WebIntelX AI backend is unreachable. Check that it is running and WEBINTELX_API_URL is correct.",
            "unauthorized": "Your session has expired. Please sign in again.",
            "llm_unavailable": "The AI investigation could not run because the language model is unavailable. Facts, risk, threat intelligence and the alert are still shown.",
            "database": "The backend reported that its database is unavailable."}.get(kind, "Something went wrong.")
    return base + (f" ({md_escape(detail, 200)})" if detail else "")


# ------------------------------------------------------------------ M10: analyst actions, lifecycle, report (appended; nothing above was changed)
STATUS_LABELS = {
    "DETECTED": "Detected", "INVESTIGATING": "Investigating", "CONFIRMED": "Confirmed (true positive)", "FALSE_POSITIVE": "False positive",
    "NEEDS_INVESTIGATION": "Needs investigation", "RESPONSE_RECOMMENDED": "Response recommended", "ACTION_TAKEN": "Action taken (by a human, outside this platform)",
    "RESOLVED": "Resolved",
}
# PRD section 21 MVP feedback vocabulary -> value sent to POST /feedback
ANALYST_DECISIONS = (("confirmed", "True positive / Confirmed"), ("false_positive", "False positive"), ("needs_investigation", "Needs investigation"))
DECISION_STATES = {"CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"}      # recorded through the feedback form, not the lifecycle-step form
RECOMMENDATION_CHOICES = (("accept", "Accept"), ("reject", "Reject"), ("further_investigation", "Further investigate"))
RECOMMENDATION_DECISION_LABELS = {"accepted": "Accepted by analyst", "rejected": "Rejected by analyst", "needs_investigation": "Analyst asked for further investigation"}
REPORT_FORMATS = {"markdown": ("md", "text/markdown"), "html": ("html", "text/html"), "json": ("json", "application/json")}


def status_label(status: str | None) -> str:
    s = (status or "DETECTED").upper()
    return STATUS_LABELS.get(s, s.replace("_", " ").title())


def lifecycle_step_options(lc: Mapping[str, Any] | None) -> list[str]:
    """Next states offered in the lifecycle-step form. The three analyst-decision states are excluded: they are recorded through the
    feedback form so the outcome is always stored (the backend enforces this too)."""
    return [s for s in (lc or {}).get("allowed_next") or [] if s not in DECISION_STATES]


def lifecycle_summary(lc: Mapping[str, Any] | None) -> dict[str, Any]:
    lc = lc or {}
    status = (lc.get("status") or "DETECTED").upper()
    fb = lc.get("latest_feedback") or {}
    return {"status": status, "status_label": status_label(status), "closed": bool(lc.get("closed")), "alert_status": lc.get("alert_status") or "n/a",
            "allowed_next": list(lc.get("allowed_next") or []), "step_options": lifecycle_step_options(lc), "feedback_count": int(lc.get("feedback_count") or 0),
            "latest_decision": fb.get("analyst_decision"), "latest_comment": fb.get("comment"), "latest_at": fb.get("created_at")}


def history_rows(lc: Mapping[str, Any] | None, limit: int = 30) -> list[dict[str, Any]]:
    """Newest first. Comments are analyst-authored plain text: callers must escape them before st.markdown (tables are safe)."""
    rows = [{"at": h.get("at"), "from": h.get("from"), "to": h.get("to"), "actor": h.get("actor"), "reason": h.get("reason"), "comment": h.get("comment") or ""}
            for h in (lc or {}).get("history") or []]
    return list(reversed(rows))[:limit]


def feedback_rows(feedback: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    return [{"at": f.get("created_at"), "decision": f.get("analyst_decision"), "comment": f.get("comment") or "", "feedback_id": f.get("feedback_id")}
            for f in (feedback or {}).get("feedback") or []]


def recommendation_decision_rows(rec: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """One row per proposed action with the analyst's decision overlay (AC-19). `executed` is always False here: the platform executes nothing."""
    out = []
    for r in sorted((rec or {}).get("recommendations") or [], key=lambda r: r.get("priority") or 99):
        d = r.get("analyst_decision") if isinstance(r.get("analyst_decision"), Mapping) else None
        key = (d or {}).get("decision")
        out.append({"action": r.get("action"), "title": r.get("title") or r.get("action") or "", "priority": r.get("priority"),
                    "decision": key, "decision_label": RECOMMENDATION_DECISION_LABELS.get(key, "Awaiting analyst decision"),
                    "comment": (d or {}).get("comment") or "", "decided_at": (d or {}).get("decided_at"), "executed": False})
    return out


def approval_progress(rows: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    rows = list(rows or [])
    accepted = [r for r in rows if r.get("decision") == "accepted"]
    return {"total": len(rows), "accepted": len(accepted), "pending": sum(1 for r in rows if not r.get("decision")),
            "can_record_action_taken": (not rows) or bool(accepted)}


def report_download(incident_id: str, fmt: str) -> dict[str, str]:
    """File name and MIME type for a report download. The id is reduced to a safe file-name stem."""
    if fmt not in REPORT_FORMATS:
        raise ValueError("unknown report format")
    ext, mime = REPORT_FORMATS[fmt]
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", str(incident_id or "incident"))[:80] or "incident"
    return {"file_name": f"{stem}-report.{ext}", "mime": mime}


def action_error_text(kind: str, message: str | None, code: str | None = None) -> str:
    """Text for a refused analyst action (409 invalid_transition / approval_required, 422 comment rules, ...). The message is code-authored by
    the backend but still escaped; connection-level problems reuse `error_banner`."""
    if kind in ("backend_down", "unauthorized", "database"):
        return error_banner(kind, message if kind != "unauthorized" else None)
    prefix = {"approval_required": "Approval needed: ", "invalid_transition": "Not allowed from the current state: ",
              "comment_required": "Comment needed: "}.get(code or "", "Request refused: ")
    return prefix + md_escape(message or "no details", 500)
