"""Threat-intelligence endpoints (FR-13, AC-11).

Isolation (FR-27 / AC-22): incident routes join Website.account_id to the caller's account and answer 404
(not 403) for other customers' incidents; website routes use `get_owned_website`. No endpoint returns a credential.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.correlation import _owned_incident
from app.api.deps import get_current_account, get_owned_website
from app.config import get_settings
from app.database.database import get_db
from app.database.models import Account, Incident, Website
from app.threat_intel.config import get_ti_config
from app.threat_intel.providers import build_providers
from app.threat_intel.service import run_enrichment, stored_report

router = APIRouter(tags=["threat-intel"])


@router.get("/v1/threat-intel/providers")
def providers_status() -> dict:
    """Which providers are active and the configuration in force (public; booleans only, no secrets)."""
    s, cfg = get_settings(), get_ti_config()
    return {"config": cfg.public(), "providers": build_providers(s, cfg, s.nvd_api_key).public(),
            "note": "Threat-intelligence results are third-party context, never AI conclusions. No evidence found does not mean safe or malicious."}


@router.post("/v1/incidents/{incident_id}/threat-intel")
def enrich_incident(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    """Enrich the incident's indicators (idempotent: replaces the previous report). Provider failures are reported, not raised."""
    return run_enrichment(db, _owned_incident(db, account, incident_id))


@router.get("/v1/incidents/{incident_id}/threat-intel")
def get_incident_threat_intel(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    return stored_report(_owned_incident(db, account, incident_id))


@router.post("/v1/websites/{website_id}/threat-intel/enrich")
def enrich_website_incidents(site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
                             limit: int = Query(10, ge=1, le=50)) -> dict:
    """Enrich this website's most recent incidents (demo / orchestrator convenience)."""
    incs = db.scalars(select(Incident).where(Incident.website_id == site.website_id).order_by(Incident.created_at.desc()).limit(limit)).all()
    reports = [run_enrichment(db, i) for i in incs]
    return {"website_id": site.website_id, "incidents": len(reports),
            "reports": [{"incident_id": r["incident_id"], "status": r["status"], "counts": r.get("counts", {}),
                         "contains_synthetic": r.get("contains_synthetic", False)} for r in reports]}
