"""Incident read endpoints. Incident creation arrives in later milestones; these
endpoints already enforce website isolation (FR-27, AC-22)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_account, get_owned_website
from app.database.database import get_db
from app.database.models import Account, Incident, Website

router = APIRouter(tags=["incidents"])


def _out(i: Incident) -> dict:
    return {
        "incident_id": i.incident_id,
        "website_id": i.website_id,
        "title": i.title,
        "risk_level": i.risk_level,
        "risk_score": i.risk_score,
        "confidence": i.confidence,
        "status": i.status,
        "details": i.details,
        "created_at": i.created_at,
        "updated_at": i.updated_at,
    }


@router.get("/v1/websites/{website_id}/incidents")
def list_incidents(site: Website = Depends(get_owned_website), db: Session = Depends(get_db),
                   risk_level: str | None = Query(None, pattern="^(?i:low|medium|high|critical)$"),
                   sort: str = Query("created", pattern="^(created|risk)$")) -> list[dict]:
    """`risk_level` filters on the stored level; `sort=risk` puts the highest risk score first (unscored incidents last)."""
    q = select(Incident).where(Incident.website_id == site.website_id)
    if risk_level:
        q = q.where(Incident.risk_level == risk_level.upper())
    q = q.order_by(Incident.risk_score.is_(None), Incident.risk_score.desc(), Incident.created_at.desc()) if sort == "risk" \
        else q.order_by(Incident.created_at.desc())
    return [_out(i) for i in db.scalars(q).all()]


@router.get("/v1/incidents/{incident_id}")
def get_incident(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = db.scalar(
        select(Incident)
        .join(Website, Website.website_id == Incident.website_id)
        .where(Incident.incident_id == incident_id, Website.account_id == account.account_id)
    )
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _out(inc)
