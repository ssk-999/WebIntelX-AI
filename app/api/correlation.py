"""Correlation endpoints (FR-12, FR-14, FR-15, AC-09, AC-12, AC-13).

Isolation (FR-27 / AC-22): website routes use `get_owned_website`; incident routes join Website.account_id to the
caller's account and answer 404 (not 403) for other customers' incidents. Every event/finding query is scoped to
the incident's website_id.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_account, get_owned_website
from app.correlation.attack_graph import build_graph, build_timeline
from app.correlation.config import get_correlation_config
from app.correlation.engine import Link, finding_view, load_findings, run_correlation
from app.database.database import get_db
from app.database.models import Account, Correlation, Event, Incident, Website

router = APIRouter(tags=["correlation"])
_CHUNK = 500


@router.get("/v1/correlation/config")
def correlation_config() -> dict:
    """Correlation configuration in force (public; no secrets)."""
    return {"config": get_correlation_config().public(),
            "note": "Strength is a documented heuristic in [0,1], not a probability. Correlation is deterministic: no LLM is involved."}


@router.post("/v1/websites/{website_id}/correlate")
def correlate_website(site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
                      top: int = Query(20, ge=1, le=100)) -> dict:
    """Correlate this website's findings into clusters and potential incidents (idempotent)."""
    rep = run_correlation(db, site.website_id).to_dict()
    rep["cluster_summaries"] = rep["cluster_summaries"][:top]
    return {"website_id": site.website_id, **rep}


def _owned_incident(db: Session, account: Account, incident_id: str) -> Incident:
    inc = db.scalar(select(Incident).join(Website, Website.website_id == Incident.website_id)
                    .where(Incident.incident_id == incident_id, Website.account_id == account.account_id))
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


def _incident_events(db: Session, inc: Incident) -> list[Event]:
    ids = list((inc.details or {}).get("event_ids") or [])
    out: list[Event] = []
    for i in range(0, len(ids), _CHUNK):
        out += list(db.scalars(select(Event).where(Event.website_id == inc.website_id, Event.event_id.in_(ids[i:i + _CHUNK]))))
    return sorted(out, key=lambda e: (e.timestamp, e.event_id))


def _links(db: Session, inc: Incident) -> list[Correlation]:
    return list(db.scalars(select(Correlation).where(Correlation.website_id == inc.website_id, Correlation.incident_id == inc.incident_id)
                           .order_by(Correlation.correlation_id)))


@router.get("/v1/incidents/{incident_id}/correlations")
def incident_correlations(incident_id: str, relationship_type: str | None = None,
                          account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    rows = [c for c in _links(db, inc) if relationship_type in (None, c.relationship_type)]
    ev = {e.event_id: e for e in _incident_events(db, inc)}
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    rows.sort(key=lambda c: (ev[c.event_id].timestamp if c.event_id in ev else epoch, c.event_id, c.related_event_id, c.relationship_type))
    return {"incident_id": inc.incident_id, "count": len(rows),
            "by_type": (inc.details or {}).get("link_counts", {}), "links_truncated": (inc.details or {}).get("links_truncated", False),
            "correlations": [{"correlation_id": c.correlation_id, "event_id": c.event_id, "related_event_id": c.related_event_id,
                              "relationship_type": c.relationship_type, "strength": c.strength} for c in rows]}


def _views(db: Session, inc: Incident, events: list[Event]):
    return [finding_view(f) for f in load_findings(db, inc.website_id, [e.event_id for e in events])]


@router.get("/v1/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    events = _incident_events(db, inc)
    entries = build_timeline(events, _views(db, inc, events), incident_created_at=inc.created_at,
                             enrichment=(inc.details or {}).get("threat_intel"),
                             investigation=(inc.details or {}).get("investigation"))
    return {"incident_id": inc.incident_id, "entry_count": len(entries), "timeline": entries,
            "note": "evidence_type: observed = recorded events; derived_indicator = rule/model output (not proof); ai_inference = AI agent output (not proof); system = platform action."}


@router.get("/v1/incidents/{incident_id}/graph")
def incident_graph(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    events = _incident_events(db, inc)
    links = [Link(c.event_id, c.related_event_id, c.relationship_type, c.strength or 0.0) for c in _links(db, inc)]
    return build_graph(events, _views(db, inc, events), links, incident_id=inc.incident_id, title=inc.title)
