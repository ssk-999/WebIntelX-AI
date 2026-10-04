"""Detection engine: load events -> run rules -> persist findings (PRD section 11 'Rules + ML', FR-11).

Findings are stored in the PRD `findings` table with agent_name="rule_engine" (deterministic code, not an
LLM; CrewAI agents added later write their own findings under their own names).

Idempotent: re-analysing the same events first deletes this engine's previous findings anchored on those
events, so repeated runs never duplicate. Only `rule_engine` rows are ever deleted.

Scope: a full-website run, or an incremental run for the source addresses / sessions touched by a new
batch (loads ALL their events inside the lookback window so windowed rules see the whole picture).
PRD does not specify incremental behaviour; this is the implementation assumption.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.database.models import Event, Finding
from app.detection.config import DetectionConfig, get_detection_config
from app.detection.rules import FindingDraft, evaluate

log = logging.getLogger("webintelx.detection")
RULE_ENGINE = "rule_engine"
_CHUNK = 500


@dataclass
class DetectionResult:
    events_analyzed: int = 0
    findings_created: int = 0
    findings_replaced: int = 0
    suspicious_events: int = 0              # distinct events that are a finding anchor OR cited as finding evidence
    finding_anchor_events: int = 0          # distinct events a finding is attached to
    by_rule: dict[str, int] = field(default_factory=dict)
    by_finding_type: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "events_analyzed": self.events_analyzed, "findings_created": self.findings_created,
            "findings_replaced": self.findings_replaced, "suspicious_events": self.suspicious_events,
            "finding_anchor_events": self.finding_anchor_events, "by_rule": dict(sorted(self.by_rule.items())),
            "by_finding_type": dict(sorted(self.by_finding_type.items())),
        }


def _chunks(seq: Sequence, n: int = _CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def load_events(db: Session, website_id: str, *, ips: Iterable[str] | None = None,
                session_ids: Iterable[str] | None = None, since: datetime | None = None) -> list[Event]:
    """Website-scoped load (isolation: every query is filtered by website_id)."""
    base = select(Event).where(Event.website_id == website_id)
    if since is not None:
        base = base.where(Event.timestamp >= since)
    if ips is None and session_ids is None:
        return list(db.scalars(base.order_by(Event.timestamp, Event.event_id)))
    ips, sids = sorted({i for i in (ips or []) if i}), sorted({s for s in (session_ids or []) if s})
    found: dict[str, Event] = {}
    for chunk in _chunks(ips):
        for e in db.scalars(base.where(Event.source_ip.in_(chunk))):
            found[e.event_id] = e
    for chunk in _chunks(sids):
        for e in db.scalars(base.where(Event.session_id.in_(chunk))):
            found[e.event_id] = e
    return sorted(found.values(), key=lambda e: (e.timestamp, e.event_id))


def _persist(db: Session, events: Sequence[Event], drafts: Sequence[FindingDraft]) -> int:
    ids = [e.event_id for e in events]
    replaced = 0
    for chunk in _chunks(ids):
        replaced += db.execute(
            delete(Finding).where(Finding.agent_name == RULE_ENGINE, Finding.event_id.in_(chunk))
        ).rowcount or 0
    db.add_all(
        Finding(event_id=d.event_id, agent_name=RULE_ENGINE, finding_type=d.finding_type,
                confidence=d.confidence, evidence=d.evidence)
        for d in drafts
    )
    db.commit()
    return replaced


def run_detection(db: Session, website_id: str, *, ips: Iterable[str] | None = None,
                  session_ids: Iterable[str] | None = None, since: datetime | None = None,
                  cfg: DetectionConfig | None = None) -> DetectionResult:
    cfg = cfg or get_detection_config()
    events = load_events(db, website_id, ips=ips, session_ids=session_ids, since=since)
    res = DetectionResult(events_analyzed=len(events))
    if not events:
        return res
    drafts = evaluate(events, cfg)
    res.findings_replaced = _persist(db, events, drafts)
    res.findings_created = len(drafts)
    flagged: set[str] = set()
    anchors: set[str] = set()
    for d in drafts:
        anchors.add(d.event_id)
        flagged.add(d.event_id)
        flagged.update(d.evidence.get("event_ids", []))
        res.by_rule[d.rule_id] = res.by_rule.get(d.rule_id, 0) + 1
        res.by_finding_type[d.finding_type] = res.by_finding_type.get(d.finding_type, 0) + 1
    res.suspicious_events, res.finding_anchor_events = len(flagged), len(anchors)
    return res


def run_detection_for_events(db: Session, website_id: str, new_events: Sequence[Event],
                             cfg: DetectionConfig | None = None) -> DetectionResult:
    """Incremental analysis for a freshly ingested batch (see module docstring)."""
    cfg = cfg or get_detection_config()
    if not new_events:
        return DetectionResult()
    newest = max(e.timestamp for e in new_events)
    since = newest - timedelta(hours=cfg["analysis_window_hours"])
    return run_detection(
        db, website_id, ips={e.source_ip for e in new_events if e.source_ip},
        session_ids={e.session_id for e in new_events if e.session_id}, since=since, cfg=cfg,
    )


def count_findings(db: Session, website_id: str) -> int:
    return db.scalar(
        select(func.count(Finding.finding_id)).join(Event, Event.event_id == Finding.event_id).where(Event.website_id == website_id)
    ) or 0
