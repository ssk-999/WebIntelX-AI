"""Anomaly engine: load events -> sessionise -> Isolation Forest -> persist findings (PRD section 11 'Rules + ML').

Findings go to the PRD `findings` table with agent_name="anomaly_model". Idempotent: a successful run first
deletes ONLY this engine's previous findings anchored on the analysed events, then writes the new ones, so
repeated runs never duplicate and rule_engine findings are never touched.

If the analysis cannot run (disabled / too few sessions / model unavailable / error) nothing is written or
deleted, and the report says why: earlier findings stay as they were, and rule detection is unaffected.
Every query is website-scoped (FR-27). PRD does not specify when ML runs; assumption: on demand via the API
(and, from milestone 8, by the orchestrator) rather than on every ingested batch, because the baseline is
fitted over the whole window and refitting per 20-event batch would make scores drift while data streams in.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.database.models import Finding
from app.detection.engine import load_events
from app.ml.anomaly_model import AGENT_NAME, AnomalyReport, analyze_events
from app.ml.config import AnomalyConfig, get_anomaly_config

log = logging.getLogger("webintelx.ml.engine")
_CHUNK = 500


def _chunks(seq: Sequence, n: int = _CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def run_anomaly_detection(db: Session, website_id: str, *, since: datetime | None = None,
                          cfg: AnomalyConfig | None = None) -> AnomalyReport:
    cfg = cfg or get_anomaly_config()
    if not cfg["enabled"]:
        return AnomalyReport(status="disabled")
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(hours=cfg["window_hours"])
    events = load_events(db, website_id, since=since)
    report = analyze_events(events, cfg)
    if report.status != "ok":
        return report

    ids = [e.event_id for e in events]
    replaced = 0
    for chunk in _chunks(ids):
        replaced += db.execute(
            delete(Finding).where(Finding.agent_name == AGENT_NAME, Finding.event_id.in_(chunk))
        ).rowcount or 0
    db.add_all(
        Finding(event_id=d.event_id, agent_name=AGENT_NAME, finding_type=d.finding_type,
                confidence=d.confidence, evidence=d.evidence)
        for d in report.drafts
    )
    db.commit()
    report.findings_created, report.findings_replaced = len(report.drafts), replaced
    return report
