"""Incident lifecycle, analyst feedback and recommendation decisions (FR-22, FR-23, AC-19, AC-20). Deterministic; no LLM.

Storage (no schema change; PRD section 30 `feedback` table is used as designed):
  feedback table                      one row per analyst decision (permanent record of the outcome, AC-20)
  incident.status                     the lifecycle state (PRD section 22)
  details["lifecycle"]["history"]     every status change: at / from / to / actor / reason / feedback_id (last `HISTORY_MAX`)
  details["recommendation_decisions"] analyst decision per recommended action (accepted | rejected | needs_investigation), keyed by action
  details["audit"]                    append-only trail shared with M8 (PRD sections 33, 35): analyst and system entries, `actor` says who
  details["alert"]["status"]          open | acknowledged | closed, following the lifecycle

Nothing here executes a response action. `ACTION_TAKEN` records that a human did something outside the platform and needs a comment, and
(when AI recommendations exist) at least one accepted recommendation first (PRD section 21: human approval before consequential action).
Keys owned by other milestones are preserved (new dict assigned so SQLAlchemy sees the JSON change).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Account, Feedback, Incident, new_id
from app.lifecycle.states import (ACTION_TAKEN, CLOSED_STATES, CONFIRMED, DECISIONS, DETECTED, INVESTIGATING, RESPONSE_RECOMMENDED,
                                  LifecycleError, alert_status_for, allowed_next, check_transition, clean_comment, normalise_decision,
                                  normalise_recommendation_decision, normalise_state)

log = logging.getLogger("webintelx.lifecycle")
HISTORY_MAX = 100
AUDIT_MAX_FALLBACK = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit_max() -> int:
    try:
        from app.agents.config import get_agents_config
        return int(get_agents_config()["orchestration"]["audit_max_entries"])
    except Exception:  # noqa: BLE001 - config trouble must not block an analyst decision
        return AUDIT_MAX_FALLBACK


def actor_of(account: Account | None) -> str:
    return f"analyst:{account.account_id}" if account is not None else "system"


def _usable_recommendations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    rec = details.get("recommendations")
    if isinstance(rec, Mapping) and rec.get("status") == "ok":
        return [r for r in (rec.get("recommendations") or []) if isinstance(r, Mapping) and r.get("action")]
    return []


def _transition(incident: Incident, details: dict[str, Any], new: str, *, actor: str, reason: str, comment: str | None = None,
                feedback_id: str | None = None, now_iso: str | None = None) -> None:
    """Validate and apply ONE state change to `details` + `incident.status` (caller commits). Raises LifecycleError."""
    now_iso = now_iso or _now()
    cur = (incident.status or DETECTED).upper()
    check_transition(cur, new)
    if new == ACTION_TAKEN:
        if not comment:
            raise LifecycleError("comment_required", "Recording ACTION_TAKEN requires a comment describing the action that was taken (audit trail).", 422)
        recs = _usable_recommendations(details)
        decided = details.get("recommendation_decisions") or {}
        if recs and not any((decided.get(r["action"]) or {}).get("decision") == "accepted" for r in recs):
            raise LifecycleError("approval_required", "No recommended response has been accepted yet. Accept at least one recommendation before recording ACTION_TAKEN (human approval, PRD section 21).",
                                 409, recommendations=[r["action"] for r in recs])
    life = dict(details.get("lifecycle") or {})
    entry = {"at": now_iso, "from": cur, "to": new, "actor": actor, "reason": reason, "comment_recorded": bool(comment)}
    if feedback_id:
        entry["feedback_id"] = feedback_id
    if comment:
        entry["comment"] = comment                        # analyst-authored plain text; renderers must escape it
    life["history"] = (list(life.get("history") or []) + [entry])[-HISTORY_MAX:]
    life["status"], life["updated_at"] = new, now_iso
    details["lifecycle"] = life
    alert = details.get("alert")
    if isinstance(alert, Mapping):
        a_new = alert_status_for(new, alert.get("status"))
        if a_new != alert.get("status"):
            details["alert"] = {**alert, "status": a_new, "updated_at": now_iso}
    audit = {"at": now_iso, "action": "status_changed", "actor": actor, "from": cur, "to": new, "reason": reason, "comment_recorded": bool(comment),
             "executed": False}
    if feedback_id:
        audit["feedback_id"] = feedback_id
    if comment:
        audit["comment"] = comment
    if new == ACTION_TAKEN:
        audit["note"] = "A human reports an action taken outside this platform; the platform executed nothing."
    details["audit"] = (list(details.get("audit") or []) + [audit])[-_audit_max():]
    incident.status = new


def record_decision(db: Session, incident: Incident, account: Account, decision: str, comment: str | None = None) -> dict[str, Any]:
    """Analyst feedback (PRD section 21): store it against the incident and move the lifecycle. All-or-nothing."""
    dec = normalise_decision(decision)
    note = clean_comment(comment)
    now_iso = _now()
    cur = (incident.status or DETECTED).upper()
    details = dict(incident.details or {})
    fb_id = new_id("fb")
    try:
        if dec != cur:                                    # repeating the current decision only stores the new feedback / comment
            _transition(incident, details, dec, actor=actor_of(account), reason="analyst_decision", comment=note, feedback_id=fb_id, now_iso=now_iso)
        details["audit"] = (list(details.get("audit") or []) + [{"at": now_iso, "action": "analyst_decision", "actor": actor_of(account), "decision": dec,
                            "feedback_id": fb_id, "comment_recorded": bool(note), "status_changed": dec != cur}])[-_audit_max():]
        advanced = False
        if dec == CONFIRMED and incident.status == CONFIRMED and _usable_recommendations(details):
            _transition(incident, details, RESPONSE_RECOMMENDED, actor="system", reason="confirmed_with_recommendations", now_iso=now_iso)
            advanced = True
        db.add(Feedback(feedback_id=fb_id, incident_id=incident.incident_id, analyst_decision=dec, comment=note))
        incident.details = details
        db.commit()
    except LifecycleError:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    db.refresh(incident)
    return {"feedback_id": fb_id, "decision": dec, "auto_advanced_to_response_recommended": advanced, **lifecycle_view(db, incident)}


def change_status(db: Session, incident: Incident, account: Account, new_state: str, comment: str | None = None) -> dict[str, Any]:
    """Manual lifecycle step. The three analyst-decision states are routed through `record_decision` so the outcome is always stored (AC-20)."""
    new = normalise_state(new_state)
    if new in DECISIONS:
        return record_decision(db, incident, account, new, comment)
    note = clean_comment(comment)
    details = dict(incident.details or {})
    try:
        _transition(incident, details, new, actor=actor_of(account), reason="analyst_status_change", comment=note)
        incident.details = details
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(incident)
    return lifecycle_view(db, incident)


def mark_investigating(db: Session, incident: Incident) -> bool:
    """System step after an investigation run: DETECTED -> INVESTIGATING (PRD section 22). Never raises, never blocks the investigation."""
    try:
        if (incident.status or DETECTED).upper() != DETECTED:
            return False
        details = dict(incident.details or {})
        _transition(incident, details, INVESTIGATING, actor="system", reason="investigation_run")
        incident.details = details
        db.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.error("could not mark %s as INVESTIGATING: %s", getattr(incident, "incident_id", "?"), type(exc).__name__)
        return False


def decide_recommendation(db: Session, incident: Incident, account: Account, action: str, decision: str, comment: str | None = None) -> dict[str, Any]:
    """Accept / reject / request further investigation of ONE proposed action (PRD section 21, AC-19). Never executes anything."""
    dec = normalise_recommendation_decision(decision)
    note = clean_comment(comment)
    details = dict(incident.details or {})
    key = (action or "").strip().lower()
    recs = _usable_recommendations(details)
    if key not in {r["action"] for r in recs}:
        raise LifecycleError("recommendation_not_found", "This incident has no recommendation with that action.", 404)
    now_iso = _now()
    decided = dict(details.get("recommendation_decisions") or {})
    decided[key] = {"action": key, "decision": dec, "comment": note, "decided_at": now_iso, "decided_by": actor_of(account), "executed": False}
    details["recommendation_decisions"] = decided
    details["audit"] = (list(details.get("audit") or []) + [{"at": now_iso, "action": "recommendation_decision", "actor": actor_of(account), "recommended_action": key,
                        "decision": dec, "comment_recorded": bool(note), "requires_human_approval": True, "executed": False}])[-_audit_max():]
    try:
        incident.details = details
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"incident_id": incident.incident_id, "action": key, "decision": dec, "executed": False,
            "note": "Recorded. Accepting a recommendation is an approval by a human; the platform does not execute response actions."}


def overlay_decisions(recommendations: list[Mapping[str, Any]], details: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Adds `analyst_decision` (or None) to each proposed recommendation without changing any code-fixed field."""
    decided = (details or {}).get("recommendation_decisions") or {}
    out = []
    for r in recommendations or []:
        d = decided.get(r.get("action")) if isinstance(decided, Mapping) else None
        out.append({**r, "analyst_decision": ({k: d.get(k) for k in ("decision", "comment", "decided_at", "decided_by")} if isinstance(d, Mapping) else None)})
    return out


def list_feedback(db: Session, incident: Incident) -> list[dict[str, Any]]:
    rows = db.scalars(select(Feedback).where(Feedback.incident_id == incident.incident_id).order_by(Feedback.created_at.desc(), Feedback.feedback_id))
    return [{"feedback_id": f.feedback_id, "incident_id": f.incident_id, "analyst_decision": f.analyst_decision, "comment": f.comment, "created_at": f.created_at}
            for f in rows]


def lifecycle_view(db: Session, incident: Incident) -> dict[str, Any]:
    d = incident.details or {}
    fb = list_feedback(db, incident)
    status = (incident.status or DETECTED).upper()
    alert = d.get("alert") if isinstance(d.get("alert"), Mapping) else None
    return {"incident_id": incident.incident_id, "status": status, "closed": status in CLOSED_STATES, "allowed_next": allowed_next(status),
            "history": list((d.get("lifecycle") or {}).get("history") or []), "latest_feedback": fb[0] if fb else None, "feedback_count": len(fb),
            "recommendation_decisions": dict(d.get("recommendation_decisions") or {}), "alert_status": (alert or {}).get("status"),
            "updated_at": incident.updated_at}
