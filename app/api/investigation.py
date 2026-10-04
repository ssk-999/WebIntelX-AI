"""Investigation, recommendation and alert endpoints (PRD FR-16..FR-21, AC-10, AC-14..AC-19).

Isolation (FR-27 / AC-22): incident routes use `_owned_incident` (joins Website.account_id to the caller; 404, never 403, for other customers'
incidents); website routes use `get_owned_website`. The LLM runner is obtained from `get_runner()` at call time so tests can substitute a fake.
Nothing here executes a response action. Analyst decisions on recommendations live in app/api/lifecycle.py (M10).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.config import get_agents_config
from app.api.correlation import _owned_incident
from app.api.deps import get_current_account, get_owned_website
from app.config import get_settings
from app.crew.crew import get_runner
from app.crew.orchestration import run_investigation, run_investigation_for_website, stored_investigation
from app.database.database import get_db
from app.database.models import Account, Incident, Website
from app.lifecycle.service import overlay_decisions

router = APIRouter(tags=["investigation"])
_PRIORITY = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


@router.get("/v1/agents/config")
def agents_config() -> dict:
    """Agent configuration in force (public; no secrets, booleans for credentials)."""
    s = get_settings()
    return {"config": get_agents_config().public(),
            "llm": {"provider": s.llm_provider, "reasoning_model": s.llm_model, "fast_model": s.llm_fast_model, "configured": s.llm_configured},
            "note": ("Only investigation_agent and response_agent use an LLM; detection, anomaly, attack, threat-intelligence and risk roles are "
                     "deterministic. Recommendations are proposals that require human approval; nothing is executed.")}


@router.post("/v1/incidents/{incident_id}/investigate")
def investigate_incident(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    """Run the full workflow for one incident: anomaly -> threat intel -> risk -> AI investigation -> recommendations -> alert.
    Never raises: `status` is ok | partial | llm_unavailable | llm_error | invalid_output | rejected_ungrounded | disabled | error."""
    return run_investigation(db, _owned_incident(db, account, incident_id), get_runner())


@router.get("/v1/incidents/{incident_id}/investigation")
def get_investigation(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    return stored_investigation(inc.incident_id, inc.details)


@router.get("/v1/incidents/{incident_id}/recommendations")
def get_recommendations(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    rec = (inc.details or {}).get("recommendations")
    if not isinstance(rec, dict):
        return {"incident_id": inc.incident_id, "status": "not_run", "recommendations": [], "notes": ["No recommendations have been generated for this incident."]}
    out = {"incident_id": inc.incident_id, **rec}
    out["recommendations"] = overlay_decisions(rec.get("recommendations") or [], inc.details)      # adds `analyst_decision` (M10); code-fixed fields untouched
    return out


@router.get("/v1/incidents/{incident_id}/alert")
def get_alert(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    inc = _owned_incident(db, account, incident_id)
    alert = (inc.details or {}).get("alert")
    if not isinstance(alert, dict):
        return {"incident_id": inc.incident_id, "status": "no_alert",
                "notes": ["No alert exists. Alerts are created for incidents whose deterministic risk level is in alerting.levels (default HIGH, CRITICAL)."]}
    return alert


@router.get("/v1/incidents/{incident_id}/audit")
def get_audit(incident_id: str, account: Account = Depends(get_current_account), db: Session = Depends(get_db)) -> dict:
    """Audit trail of AI recommendations and alert changes (PRD sections 33, 35). Analyst decisions are added in a later milestone."""
    inc = _owned_incident(db, account, incident_id)
    entries = list((inc.details or {}).get("audit") or [])
    return {"incident_id": inc.incident_id, "count": len(entries), "audit": entries}


@router.post("/v1/websites/{website_id}/investigate")
def investigate_website(site: Website = Depends(get_owned_website), db: Session = Depends(get_db), limit: int = Query(3, ge=1, le=10)) -> dict:
    """Investigate this website's highest-risk incidents (capped by orchestration.max_incidents_per_batch)."""
    return run_investigation_for_website(db, site.website_id, get_runner(), limit=limit)


@router.get("/v1/websites/{website_id}/alerts")
def website_alerts(site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    """Prioritised incident-level alerts (PRD section 20): P1 first, then by risk score."""
    alerts = [(i.details or {}).get("alert") for i in db.scalars(select(Incident).where(Incident.website_id == site.website_id))]
    alerts = [a for a in alerts if isinstance(a, dict)]
    alerts.sort(key=lambda a: (_PRIORITY.get(a.get("priority"), 9), -(a.get("risk_score") or 0), a.get("alert_id") or ""))
    return {"website_id": site.website_id, "count": len(alerts), "alerts": alerts}
