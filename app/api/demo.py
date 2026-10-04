"""Demo controls (PRD §36 demo plan: 'show normal user behaviour', 'generate suspicious
activity'). Loads clearly-labelled SYNTHETIC events; owner-only; can be disabled."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_owned_website
from app.config import get_settings
from app.database.database import get_db
from app.database.models import Website
from app.demo.loader import available_scenarios, load_scenario
from app.correlation.engine import run_correlation
from app.detection.engine import run_detection
from app.risk.scoring import run_risk_for_website

router = APIRouter(tags=["demo"])


class DemoLoadRequest(BaseModel):
    scenario: str = "all"
    analyze: bool = True   # run the detection rules after loading (demo convenience)


@router.get("/v1/demo/scenarios")
def scenarios() -> dict:
    return {"scenarios": available_scenarios(), "note": "All demo events are synthetic and flagged is_synthetic=true."}


@router.post("/v1/websites/{website_id}/demo/load")
def demo_load(body: DemoLoadRequest, site: Website = Depends(get_owned_website), db: Session = Depends(get_db)) -> dict:
    if not get_settings().enable_demo_loader:
        raise HTTPException(status_code=403, detail="Demo loader is disabled")
    try:
        result = load_scenario(db, site, body.scenario)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    result.pop("labels", None)  # ground truth is for offline evaluation only
    result["synthetic"] = True
    if body.analyze:
        result["detection"] = run_detection(db, site.website_id).to_dict()
        # Correlation is deterministic and never raises; it creates DETECTED incident candidates (no risk yet).
        corr = run_correlation(db, site.website_id).to_dict()
        corr["cluster_summaries"] = corr["cluster_summaries"][:10]
        result["correlation"] = corr
        # Risk scoring is deterministic and never raises; threat intel is on demand, so its factor is "not assessed" here.
        result["risk"] = run_risk_for_website(db, site.website_id)
    return result
