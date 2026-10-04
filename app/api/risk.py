"""Risk-scoring endpoints (FR-19, AC-16).

Isolation (FR-27 / AC-22): incident routes join Website.account_id to the caller's account and answer 404 (not 403)
for other customers' incidents; website routes use `get_owned_website`. Nothing here changes incident status.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.correlation import _owned_incident
from app.api.deps import get_current_account, get_owned_website
from app.database.database import get_db
from app.database.models import Account, Website
from app.risk.config import get_risk_config
from app.risk.scoring import run_risk, run_risk_for_website, stored_risk

router = APIRouter(tags=["risk"])


@router.get("/v1/risk/config")
def risk_config() -> dict:
    """Weights, thresholds and formulas in force (public; no secrets) so every score is reproducible."""
    return {"config": get_risk_config().public(),
            "note": "Risk is a deterministic configuration-driven heuristic and confidence is evidence quality; neither is a probability and no LLM is involved."}


@router.post("/v1/incidents/{incident_id}/risk")
def score_incident_risk(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    """Score the incident from its stored findings, correlation and threat-intel report (idempotent: replaces the previous score)."""
    return run_risk(db, _owned_incident(db, account, incident_id))


@router.get("/v1/incidents/{incident_id}/risk")
def get_incident_risk(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    return stored_risk(_owned_incident(db, account, incident_id))


@router.post("/v1/websites/{website_id}/risk/score")
def score_website_risk(site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
                       limit: int = Query(50, ge=1, le=200)) -> dict:
    """Score this website's most recent incidents (demo / orchestrator convenience)."""
    return run_risk_for_website(db, site.website_id, limit=limit)
