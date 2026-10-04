"""Supervisor / orchestrator (PRD sections 12, 13, 14, 29).

`investigate_core` is PURE (plain dicts in, plain dicts out; the LLM runner is injected) so the whole workflow is unit-testable with a fake
runner. `run_investigation` is the thin DB wrapper that gathers stored inputs, runs the deterministic prerequisite steps, calls the core and
persists the result under existing `incident.details` keys (no schema change):

    details["investigation"]    facts (deterministic) + AI inference (grounded) + validation report
    details["recommendations"]  proposed actions, always requires_human_approval, never executed
    details["alert"]            incident-level alert (deterministic risk threshold)
    details["agent_run"]        per-step status / model / attempts / duration (observability, PRD NFR)
    details["audit"]            append-only trail of recommendations / alert changes (PRD sections 33, 35); analyst decisions arrive in M10

Memory (PRD section 29): the evidence bundle is the short-term working context, kept in-process for one run. Persistent memory is the stored
incident/feedback data. The LLM has no memory of its own: every call receives only the bundle (no history, no vector store).
The only lifecycle step taken here is DETECTED -> INVESTIGATING after a run (app/lifecycle/service.py, M10); analyst decisions are never made here.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from app.agents.alerting import build_alert
from app.agents.config import AgentsConfig, get_agents_config
from app.agents.deterministic import anomaly_agent, attack_agent, detection_agent
from app.agents.evidence import build_bundle
from app.agents.investigation_agent import run_investigation_agent
from app.agents.response_agent import run_response_agent
from app.crew.crew import LLMRunner

log = logging.getLogger("webintelx.orchestration")
DISCLAIMER = ("Facts are recorded or deterministically derived. The inference section is AI-generated, evidence-referenced and not proof of an "
              "attack. Recommendations are proposals that require human approval; nothing was executed.")


def _now(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat()


def _audit(now_iso: str, action: str, **kw: Any) -> dict[str, Any]:
    return {"at": now_iso, "action": action, "actor": "system", **kw}


def investigate_core(*, incident: Mapping[str, Any], findings: Sequence[Mapping[str, Any]], timeline: Sequence[Mapping[str, Any]],
                     runner: LLMRunner, cfg: AgentsConfig | Mapping[str, Any], now: datetime | None = None,
                     prior_alert: Mapping[str, Any] | None = None) -> dict[str, Any]:
    c = cfg.data if isinstance(cfg, AgentsConfig) else cfg
    fp = cfg.fingerprint if isinstance(cfg, AgentsConfig) else "custom"
    now_iso = _now(now)
    details = dict(incident.get("details") or {})
    risk, ti = details.get("risk"), details.get("threat_intel")
    out: dict[str, Any] = {"incident_id": incident.get("incident_id"), "generated_at": now_iso, "audit": [], "investigation": None,
                           "recommendations": None, "alert": None, "error": None}
    if not c["enabled"]:
        out.update(status="disabled", agent_run={"steps": []}, error={"code": "disabled", "message": "Agent orchestration is disabled in configuration."})
        return out

    bundle = build_bundle(incident, findings, timeline, ti, risk, c)
    steps: list[dict[str, Any]] = [detection_agent(findings), anomaly_agent(findings), attack_agent(findings)]
    steps.append({"agent": "threat_intel_agent", "role": "Threat intelligence enrichment (providers; never invented)", "llm_used": False,
                  "status": (ti or {}).get("status", "not_run") if isinstance(ti, Mapping) else "not_run"})
    steps.append({"agent": "risk_agent", "role": "Documented, configuration-driven risk scoring", "llm_used": False,
                  "status": "ok" if isinstance(risk, Mapping) and risk.get("risk_level") else "not_run",
                  "risk_level": (risk or {}).get("risk_level") if isinstance(risk, Mapping) else None})
    base = {"input_fingerprint": bundle.fingerprint, "evidence_chars": bundle.chars, "context_truncated": bundle.truncated,
            "context_notes": bundle.notes, "facts": bundle.facts, "config_fingerprint": fp, "generated_at": now_iso,
            "risk_scored_at": (risk or {}).get("scored_at") if isinstance(risk, Mapping) else None,
            "event_count": int(details.get("event_count") or 0),
            "ti_retrieved_at": (ti or {}).get("retrieved_at") if isinstance(ti, Mapping) else None, "disclaimer": DISCLAIMER}
    risk_conf = (risk or {}).get("confidence") if isinstance(risk, Mapping) else None

    inv = run_investigation_agent(runner, bundle, c, risk_conf)
    steps.append(inv.step())
    if inv.status != "ok":
        out["investigation"] = {**base, "status": inv.status, "model": inv.model, "error": inv.error, "inference": None}
        out["error"], out["status"] = inv.error, inv.status
        out["audit"].append(_audit(now_iso, "ai_investigation_failed", agent="investigation_agent", model=inv.model, status=inv.status,
                                   input_fingerprint=bundle.fingerprint, config_fingerprint=fp))
        out["alert"] = build_alert(incident, risk, None, inv.status, c, prior=prior_alert, now=now)
        if out["alert"]:
            out["audit"].append(_audit(now_iso, "alert_created" if not prior_alert else "alert_updated", priority=out["alert"]["priority"], ai_status=inv.status))
        out["agent_run"] = {"steps": steps, "llm_calls": inv.attempts}
        return out

    out["investigation"] = {**base, "status": "ok", "model": inv.model, "error": None, "inference": inv.result, "validation": inv.validation}
    out["audit"].append(_audit(now_iso, "ai_investigation_generated", agent="investigation_agent", model=inv.model, input_fingerprint=bundle.fingerprint,
                               config_fingerprint=fp, validation=inv.validation))

    rsp = run_response_agent(runner, bundle, inv.result, c)
    steps.append(rsp.step())
    calls = inv.attempts + rsp.attempts
    recs: list[dict[str, Any]] | None = None
    if rsp.status == "ok":
        recs = rsp.result["recommendations"]
        out["recommendations"] = {**rsp.result, "status": "ok", "model": rsp.model, "generated_at": now_iso, "input_fingerprint": bundle.fingerprint,
                                  "config_fingerprint": fp}
        out["status"] = "ok"
        out["audit"].append(_audit(now_iso, "recommendations_proposed", agent="response_agent", model=rsp.model, count=len(recs),
                                   actions=[r["action"] for r in recs], requires_human_approval=True, executed=False,
                                   input_fingerprint=bundle.fingerprint, config_fingerprint=fp))
    else:
        out["recommendations"] = {"status": rsp.status, "error": rsp.error, "recommendations": [], "model": rsp.model, "generated_at": now_iso,
                                  "evidence_type": "recommendation", "validation": rsp.validation}
        out["status"], out["error"] = "partial", rsp.error
        out["audit"].append(_audit(now_iso, "ai_recommendations_failed", agent="response_agent", model=rsp.model, status=rsp.status,
                                   input_fingerprint=bundle.fingerprint, config_fingerprint=fp))
    out["alert"] = build_alert(incident, risk, recs, "ok" if recs else out["status"], c, prior=prior_alert, now=now)
    if out["alert"]:
        out["audit"].append(_audit(now_iso, "alert_created" if not prior_alert else "alert_updated", priority=out["alert"]["priority"],
                                   risk_level=out["alert"]["risk_level"], recommended_action=out["alert"]["recommended_next_action"]["action"]))
    out["agent_run"] = {"steps": steps, "llm_calls": calls}
    return out


def apply_outcome(details: Mapping[str, Any] | None, outcome: Mapping[str, Any], audit_max: int = 50) -> tuple[dict[str, Any], bool]:
    """Merge an investigate_core outcome into incident.details without touching keys other milestones own.
    A FAILED run never overwrites a previously successful investigation/recommendations (returns kept_previous=True)."""
    d = dict(details or {})
    kept = False
    if outcome.get("status") == "disabled":
        return d, False
    inv_new = outcome.get("investigation")
    if inv_new:
        prev = d.get("investigation")
        if inv_new.get("status") != "ok" and isinstance(prev, Mapping) and prev.get("status") == "ok":
            kept = True
        else:
            d["investigation"] = inv_new
    rec_new = outcome.get("recommendations")
    if rec_new:
        prev = d.get("recommendations")
        if rec_new.get("status") != "ok" and isinstance(prev, Mapping) and prev.get("status") == "ok":
            kept = True
        else:
            d["recommendations"] = rec_new
    if outcome.get("alert"):
        d["alert"] = outcome["alert"]
    d["agent_run"] = {**(outcome.get("agent_run") or {}), "at": outcome.get("generated_at"), "status": outcome.get("status"), "kept_previous": kept}
    d["audit"] = (list(d.get("audit") or []) + list(outcome.get("audit") or []))[-audit_max:]
    return d, kept


def stored_investigation(incident_id: str, details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Stored result plus a `stale` flag when risk / correlation / threat intel changed after it was generated."""
    d = details or {}
    inv = d.get("investigation")
    if not isinstance(inv, Mapping):
        return {"incident_id": incident_id, "status": "not_run", "notes": ["The AI investigation has not been run for this incident."],
                "agent_run": d.get("agent_run")}
    risk, ti = d.get("risk") or {}, d.get("threat_intel") or {}
    reasons = []
    if inv.get("event_count") != int(d.get("event_count") or 0):
        reasons.append("The incident's correlated events changed after the investigation.")
    if inv.get("risk_scored_at") != (risk.get("scored_at") if isinstance(risk, Mapping) else None):
        reasons.append("The incident's risk score changed after the investigation.")
    if inv.get("ti_retrieved_at") != (ti.get("retrieved_at") if isinstance(ti, Mapping) else None):
        reasons.append("The incident's threat-intelligence report changed after the investigation.")
    return {"incident_id": incident_id, **inv, "recommendations": d.get("recommendations"), "alert": d.get("alert"), "agent_run": d.get("agent_run"),
            "stale": bool(reasons), "stale_reasons": reasons}


# ------------------------------------------------------------------------------------------------------------------ DB wrapper
def _finding_dicts(db, incident) -> list[dict[str, Any]]:
    from app.correlation.engine import load_findings
    ids = list((incident.details or {}).get("event_ids") or [])
    return [{"finding_id": f.finding_id, "event_id": f.event_id, "agent_name": f.agent_name, "finding_type": f.finding_type,
             "confidence": f.confidence, "evidence": f.evidence or {}} for f in load_findings(db, incident.website_id, ids)]


def _timeline(db, incident) -> list[dict[str, Any]]:
    from sqlalchemy import select
    from app.correlation.attack_graph import build_timeline
    from app.correlation.engine import finding_view, load_findings
    from app.database.models import Event
    ids = list((incident.details or {}).get("event_ids") or [])
    events: list = []
    for i in range(0, len(ids), 500):
        events += list(db.scalars(select(Event).where(Event.website_id == incident.website_id, Event.event_id.in_(ids[i:i + 500]))))
    events.sort(key=lambda e: (e.timestamp, e.event_id))
    views = [finding_view(f) for f in load_findings(db, incident.website_id, [e.event_id for e in events])]
    return build_timeline(events, views, incident_created_at=incident.created_at, enrichment=(incident.details or {}).get("threat_intel"))


def prepare_incident(db, incident, cfg: AgentsConfig, *, run_anomaly: bool = True) -> dict[str, str]:
    """Deterministic prerequisite steps (each isolated; none can fail the investigation). Returns a status per step."""
    status: dict[str, str] = {}
    o = cfg["orchestration"]
    if o["run_anomaly"] and run_anomaly:
        try:
            from app.ml.engine import run_anomaly_detection
            status["anomaly"] = run_anomaly_detection(db, incident.website_id).status
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            status["anomaly"] = f"error:{type(exc).__name__}"
    if o["run_threat_intel"]:
        try:
            from app.threat_intel.service import run_enrichment
            status["threat_intel"] = str(run_enrichment(db, incident).get("status"))
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            status["threat_intel"] = f"error:{type(exc).__name__}"
    if o["run_risk"]:
        try:
            from app.risk.scoring import run_risk
            status["risk"] = str(run_risk(db, incident).get("status"))
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            status["risk"] = f"error:{type(exc).__name__}"
    return status


def run_investigation(db, incident, runner: LLMRunner, *, cfg: AgentsConfig | None = None, run_anomaly: bool = True) -> dict[str, Any]:
    """Full workflow for one incident. Never raises; always returns a structured result (status ok | partial | llm_unavailable | ...)."""
    cfg = cfg or get_agents_config()
    t0 = time.monotonic()
    try:
        prereq = prepare_incident(db, incident, cfg, run_anomaly=run_anomaly)
        db.refresh(incident)
        outcome = investigate_core(incident={"incident_id": incident.incident_id, "title": incident.title, "details": incident.details or {}},
                                   findings=_finding_dicts(db, incident), timeline=_timeline(db, incident), runner=runner, cfg=cfg,
                                   prior_alert=(incident.details or {}).get("alert"))
        outcome["prerequisites"] = prereq
        merged, kept = apply_outcome(incident.details, outcome, cfg["orchestration"]["audit_max_entries"])
        incident.details = merged                      # new dict object so the JSON column change is detected
        db.commit()
        if outcome["status"] != "disabled":
            from app.lifecycle.service import mark_investigating            # PRD section 22: DETECTED -> INVESTIGATING (system step, never raises)
            mark_investigating(db, incident)
        res = stored_investigation(incident.incident_id, incident.details)
        res.update(status=outcome["status"], error=outcome.get("error"), prerequisites=prereq, kept_previous_successful=kept,
                   duration_ms=int((time.monotonic() - t0) * 1000))
        log.info("investigation for %s: %s (%d ms)", incident.incident_id, outcome["status"], res["duration_ms"])
        return res
    except Exception as exc:  # noqa: BLE001 - controlled failure (PRD NFR Reliability)
        db.rollback()
        log.error("investigation failed for %s: %s", getattr(incident, "incident_id", "?"), type(exc).__name__)
        return {"incident_id": getattr(incident, "incident_id", None), "status": "error",
                "error": {"code": "error", "message": f"The investigation failed ({type(exc).__name__}); nothing was written."}}


def run_investigation_for_website(db, website_id: str, runner: LLMRunner, *, limit: int | None = None, cfg: AgentsConfig | None = None) -> dict[str, Any]:
    """Investigate the website's highest-risk incidents first (capped: LLM cost and free-tier limits)."""
    from sqlalchemy import select
    from app.database.models import Incident
    cfg = cfg or get_agents_config()
    cap = min(limit or cfg["orchestration"]["max_incidents_per_batch"], cfg["orchestration"]["max_incidents_per_batch"])
    incs = list(db.scalars(select(Incident).where(Incident.website_id == website_id)))
    incs.sort(key=lambda i: (-(i.risk_score or 0.0), i.incident_id))
    results = []
    for n, inc in enumerate(incs[:cap]):
        r = run_investigation(db, inc, runner, cfg=cfg, run_anomaly=(n == 0))     # the anomaly model is website-wide: run it once
        results.append({k: r.get(k) for k in ("incident_id", "status", "error", "duration_ms", "kept_previous_successful")})
    return {"website_id": website_id, "incidents_total": len(incs), "investigated": len(results), "cap": cap, "results": results,
            "note": "Highest-risk incidents are investigated first; the cap protects LLM cost and free-tier rate limits (config/agents.yaml orchestration.max_incidents_per_batch)."}
