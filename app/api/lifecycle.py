"""Incident lifecycle, analyst feedback and report endpoints (FR-22, FR-23, FR-24, AC-19, AC-20, AC-21).

Isolation (FR-27 / AC-22): every incident route uses `_owned_incident` (joins Website.account_id to the caller; 404, never 403, for other customers'
incidents). Nothing here executes a response action: accepting a recommendation or recording ACTION_TAKEN only records a human decision.
Controlled errors: 404 unknown incident / recommendation, 409 `invalid_transition` / `approval_required`, 422 bad input.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.correlation import _incident_events, _links, _owned_incident, _views
from app.api.deps import get_current_account
from app.correlation.attack_graph import build_graph, build_timeline
from app.correlation.engine import Link
from app.crew.orchestration import stored_investigation
from app.database.database import get_db
from app.database.models import Account, Incident
from app.lifecycle import service
from app.lifecycle.states import LifecycleError, public_config
from app.report.builder import build_report
from app.report.render import CSP, to_html, to_markdown

router = APIRouter(tags=["lifecycle"])


class FeedbackIn(BaseModel):
    decision: str = Field(max_length=40, description="confirmed (or true_positive) | false_positive | needs_investigation")
    comment: str | None = Field(default=None, max_length=5000)


class StatusIn(BaseModel):
    status: str = Field(max_length=40)
    comment: str | None = Field(default=None, max_length=5000)


class RecommendationDecisionIn(BaseModel):
    decision: str = Field(max_length=40, description="accept | reject | further_investigation")
    comment: str | None = Field(default=None, max_length=5000)


def _http(exc: LifecycleError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message, **exc.extra})


@router.get("/v1/lifecycle/config")
def lifecycle_config() -> dict:
    """States, allowed transitions and decisions in force (public; no secrets)."""
    return public_config()


@router.get("/v1/incidents/{incident_id}/lifecycle")
def get_lifecycle(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    return service.lifecycle_view(db, _owned_incident(db, account, incident_id))


@router.post("/v1/incidents/{incident_id}/status")
def set_status(incident_id: str, body: StatusIn, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    """Move the incident along PRD section 22. The decision states (CONFIRMED / FALSE_POSITIVE / NEEDS_INVESTIGATION) are stored as feedback too."""
    inc = _owned_incident(db, account, incident_id)
    try:
        return service.change_status(db, inc, account, body.status, body.comment)
    except LifecycleError as exc:
        raise _http(exc) from exc


@router.post("/v1/incidents/{incident_id}/feedback", status_code=201)
def post_feedback(incident_id: str, body: FeedbackIn, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    """Analyst outcome (PRD section 21): stored against the incident (feedback table) and applied to the lifecycle."""
    inc = _owned_incident(db, account, incident_id)
    try:
        return service.record_decision(db, inc, account, body.decision, body.comment)
    except LifecycleError as exc:
        raise _http(exc) from exc


@router.get("/v1/incidents/{incident_id}/feedback")
def get_feedback(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    rows = service.list_feedback(db, inc)
    return {"incident_id": inc.incident_id, "count": len(rows), "feedback": rows,
            "note": "Stored for later tuning of rules, prompts and baselines. There is no autonomous online learning loop (PRD section 21)."}


@router.post("/v1/incidents/{incident_id}/recommendations/{action}/decision")
def decide_recommendation(incident_id: str, action: str, body: RecommendationDecisionIn, account: Account = Depends(get_current_account),
                          db: Session = Depends(get_db)) -> dict:
    """Accept / reject / request further investigation of one proposed action (AC-19). Nothing is executed."""
    inc = _owned_incident(db, account, incident_id)
    try:
        return service.decide_recommendation(db, inc, account, action, body.decision, body.comment)
    except LifecycleError as exc:
        raise _http(exc) from exc


def build_incident_report(db: Session, inc: Incident) -> dict:
    events = _incident_events(db, inc)
    details = inc.details or {}
    views = _views(db, inc, events)
    timeline = build_timeline(events, views, incident_created_at=inc.created_at, enrichment=details.get("threat_intel"),
                              investigation=details.get("investigation"))
    graph = build_graph(events, views, [Link(c.event_id, c.related_event_id, c.relationship_type, c.strength or 0.0) for c in _links(db, inc)],
                        incident_id=inc.incident_id, title=inc.title)
    stored = stored_investigation(inc.incident_id, details)
    incident = {"incident_id": inc.incident_id, "website_id": inc.website_id, "title": inc.title, "status": inc.status, "risk_level": inc.risk_level,
                "risk_score": inc.risk_score, "confidence": inc.confidence, "details": details, "created_at": inc.created_at}
    return build_report(incident=incident, timeline=timeline, graph=graph, feedback=service.list_feedback(db, inc), investigation=stored,
                        stale_reasons=stored.get("stale_reasons") or [])


@router.get("/v1/incidents/{incident_id}/report", response_model=None)
def get_report(incident_id: str, format: str = Query("json", pattern="^(json|markdown|html)$"), download: bool = Query(False),
               account: Account = Depends(get_current_account), db: Session = Depends(get_db)):
    """Structured, shareable incident report (PRD section 24). Generated on request from stored data (deterministic, no LLM, nothing is written)."""
    inc = _owned_incident(db, account, incident_id)
    report = build_incident_report(db, inc)
    if format == "json":
        return report
    headers = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{inc.incident_id}-report.{"md" if format == "markdown" else "html"}"'
    if format == "markdown":
        return PlainTextResponse(to_markdown(report), media_type="text/markdown; charset=utf-8", headers=headers)
    return HTMLResponse(to_html(report), headers=headers)
