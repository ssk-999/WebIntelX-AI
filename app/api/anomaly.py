"""Anomaly (ML) endpoints: run the session anomaly model, list its findings (FR-10, AC-07).

Every query is scoped to the caller's own website (FR-27 / AC-22): `get_owned_website` returns 404 for other
customers' websites and every DB query filters by website_id.
"""
from __future__ import annotations

import importlib.util

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_owned_website
from app.api.detection import _finding_out
from app.database.database import get_db
from app.database.models import Event, Finding, Website
from app.ml.anomaly_model import AGENT_NAME
from app.ml.config import get_anomaly_config
from app.ml.engine import run_anomaly_detection
from app.ml.preprocessing import FEATURES

router = APIRouter(tags=["anomaly"])


@router.get("/v1/anomaly/config")
def anomaly_config() -> dict:
    """Model configuration in force and the feature list (public; contains no secrets)."""
    cfg = get_anomaly_config()
    return {
        "model_available": importlib.util.find_spec("sklearn") is not None,
        "config": cfg.public(),
        "features": [{"name": f.name, "direction": f.direction, "description": f.description} for f in FEATURES],
        "note": "Scores are relative to each website's own sessions and are not probabilities of attack.",
    }


@router.post("/v1/websites/{website_id}/anomalies/analyze")
def analyze_anomalies(site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
                      top: int = Query(10, ge=1, le=100)) -> dict:
    """Fit the baseline on this website's recent sessions and store a finding per anomalous session (idempotent)."""
    report = run_anomaly_detection(db, site.website_id)
    return {"website_id": site.website_id, **report.to_dict(top_n=top)}


@router.get("/v1/websites/{website_id}/anomalies")
def list_anomalies(
    site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
) -> list[dict]:
    q = (select(Finding, Event.timestamp).join(Event, Event.event_id == Finding.event_id)
         .where(Event.website_id == site.website_id, Finding.agent_name == AGENT_NAME,
                Finding.confidence >= min_confidence))
    rows = db.execute(q.order_by(Finding.confidence.desc(), Finding.finding_id).limit(limit).offset(offset)).all()
    return [_finding_out(f, ts) for f, ts in rows]
