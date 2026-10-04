"""Detection endpoints: run analysis, list findings, inspect sessions (FR-09/10/11, AC-07/08 rule part).

Every query is scoped to the caller's own website (FR-27 / AC-22): `get_owned_website` returns 404 for
other customers' websites, and every DB query below filters by website_id.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_owned_website
from app.database.database import get_db
from app.database.models import Event, Finding, Website
from app.detection.config import get_detection_config
from app.detection.engine import load_events, run_detection
from app.detection.rules import RULES
from app.pipeline.sessionization import session_key, sessionize

router = APIRouter(tags=["detection"])


def _finding_out(f: Finding, ts: datetime | None = None) -> dict:
    ev = f.evidence or {}
    return {
        "finding_id": f.finding_id, "event_id": f.event_id, "event_timestamp": ts, "agent_name": f.agent_name,
        "finding_type": f.finding_type, "rule_id": ev.get("rule_id"), "category": ev.get("category"),
        "confidence": f.confidence, "evidence": ev, "created_at": f.created_at,
    }


@router.get("/v1/detection/rules")
def list_rules() -> dict:
    """Rule catalogue + the thresholds currently in force (no secrets here)."""
    cfg = get_detection_config()
    return {
        "config_status": cfg.status, "config_error": cfg.error, "config_version": cfg["version"],
        "note": "Confidence is a configured rule weight, not a probability. Findings are indicators, not proof.",
        "rules": [
            {"rule_id": m.rule_id, "title": m.title, "finding_type": m.finding_type, "category": m.category,
             "description": m.description, "enabled": cfg.enabled(m.rule_id),
             "thresholds": {k: v for k, v in cfg.rule(m.rule_id).items() if k != "enabled"},
             "mitre_reference": {"technique_id": m.mitre[0], "name": m.mitre[1]} if m.mitre else None}
            for m in RULES.values()
        ],
    }


@router.post("/v1/websites/{website_id}/analyze")
def analyze(site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    """Run the deterministic detection rules over all of this website's events (idempotent)."""
    res = run_detection(db, site.website_id)
    return {"website_id": site.website_id, **res.to_dict(),
            "note": "suspicious_events counts events that carry a finding or are cited as evidence by one."}


@router.get("/v1/websites/{website_id}/findings")
def list_findings(
    site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
    finding_type: str | None = None, event_id: str | None = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
) -> list[dict]:
    q = (select(Finding, Event.timestamp).join(Event, Event.event_id == Finding.event_id)
         .where(Event.website_id == site.website_id, Finding.confidence >= min_confidence))
    if finding_type:
        q = q.where(Finding.finding_type == finding_type)
    if event_id:
        q = q.where(Finding.event_id == event_id)
    rows = db.execute(q.order_by(Event.timestamp.desc(), Finding.finding_id).limit(limit).offset(offset)).all()
    return [_finding_out(f, ts) for f, ts in rows]


def _findings_by_session(db: Session, site_id: str, events: list[Event]) -> dict[str, list[Finding]]:
    key_of = {e.event_id: session_key(e)[0] for e in events}
    if not key_of:
        return {}
    since = min(e.timestamp for e in events)
    q = (select(Finding).join(Event, Event.event_id == Finding.event_id)
         .where(Event.website_id == site_id, Event.timestamp >= since))
    out: dict[str, list[Finding]] = {}
    for f in db.scalars(q):
        k = key_of.get(f.event_id)
        if k:
            out.setdefault(k, []).append(f)
    return out


@router.get("/v1/websites/{website_id}/sessions")
def list_sessions(
    site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=168), suspicious_only: bool = False,
    sort: str = Query("recent", pattern="^(recent|findings|events)$"),
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
) -> list[dict]:
    """Derived session context (not stored). `suspicious_only` keeps sessions that have >=1 finding."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = load_events(db, site.website_id, since=since)
    sessions = sessionize(events)
    fmap = _findings_by_session(db, site.website_id, events)
    rows = []
    for key, s in sessions.items():
        fs = fmap.get(key, [])
        if suspicious_only and not fs:
            continue
        d = s.to_dict()
        d.update(finding_count=len(fs), rule_ids=sorted({(f.evidence or {}).get("rule_id", "?") for f in fs}),
                 max_finding_confidence=max((f.confidence or 0 for f in fs), default=None))
        rows.append(d)
    keyfn = {"recent": lambda r: r["last_seen"], "events": lambda r: r["event_count"],
             "findings": lambda r: (r["finding_count"], r["last_seen"])}[sort]
    rows.sort(key=keyfn, reverse=True)
    return rows[offset: offset + limit]


@router.get("/v1/websites/{website_id}/sessions/{key:path}")
def get_session(key: str, site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    q = select(Event).where(Event.website_id == site.website_id)
    if key.startswith("ip:"):
        q = q.where(Event.session_id.is_(None), Event.source_ip == key[3:])
    elif key == "unknown":
        q = q.where(Event.session_id.is_(None), Event.source_ip.is_(None))
    else:
        q = q.where(Event.session_id == key)
    events = list(db.scalars(q.order_by(Event.timestamp, Event.event_id)))
    if not events:
        raise HTTPException(status_code=404, detail="Session not found")
    ctx = sessionize(events)[session_key(events[0])[0]]
    ids = [e.event_id for e in events]
    findings = []
    for i in range(0, len(ids), 500):
        findings += list(db.scalars(select(Finding).where(Finding.event_id.in_(ids[i:i + 500]))))
    ts = {e.event_id: e.timestamp for e in events}
    return {"session": ctx.to_dict(include_event_ids=True),
            "findings": sorted((_finding_out(f, ts.get(f.event_id)) for f in findings), key=lambda x: (x["event_timestamp"], x["finding_id"]))}
