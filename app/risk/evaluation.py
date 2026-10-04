"""Offline run of the whole deterministic pipeline on the SYNTHETIC demo data, ending in risk scores (PRD sections 17, 20, 39).

HONESTY NOTE: weights and level thresholds were chosen while looking at this same synthetic data (3 incidents), so this output
shows the method behaves as designed on controlled data. It is NOT validation of the scoring on real traffic, and there is no
ground-truth severity label to evaluate against. The PRD's 10,000 -> 47 -> 8 -> 3 -> 1 funnel is a demo target, not a claim.

Run:  python -m app.risk.evaluation      (loads ALL demo data into a throw-away in-memory DB)
"""
from __future__ import annotations

from typing import Any


def summarize(db: Any, website_id: str, risk_summary: dict[str, Any]) -> dict[str, Any]:
    """Funnel counts plus the per-incident score table, from a populated database."""
    from sqlalchemy import func, select

    from app.database.models import Event, Finding, Incident

    events = db.scalar(select(func.count(Event.event_id)).where(Event.website_id == website_id)) or 0
    suspicious = len({i for (i,) in db.execute(select(Finding.event_id).join(Event, Event.event_id == Finding.event_id).where(Event.website_id == website_id))})
    incidents = list(db.scalars(select(Incident).where(Incident.website_id == website_id)))
    return {"events": events, "events_with_findings": suspicious, "incidents": len(incidents), "high_risk_incidents": risk_summary.get("high_risk", 0),
            "by_level": risk_summary.get("by_level", {}),
            "incidents_detail": [{"title": i.title[:70], "risk_level": i.risk_level, "risk_score": i.risk_score, "confidence": i.confidence,
                                  "factor_points": {f["factor"]: f["points"] for f in (i.details or {}).get("risk", {}).get("factors", [])}}
                                 for i in sorted(incidents, key=lambda i: -(i.risk_score or 0))],
            "caveat": "Synthetic data; weights/thresholds were tuned while looking at it. Not a real-world accuracy claim."}


def main() -> None:  # pragma: no cover
    import json

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.correlation.engine import run_correlation
    from app.database import models
    from app.database.database import Base
    from app.demo.loader import load_scenario
    from app.detection.engine import run_detection
    from app.ml.engine import run_anomaly_detection
    from app.risk.scoring import run_risk_for_website

    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    with sessionmaker(bind=eng, expire_on_commit=False)() as db:
        acc = models.Account(email="eval@example.com", password_hash="x")
        db.add(acc)
        db.flush()
        site = models.Website(account_id=acc.account_id, domain="eval.example.com")
        db.add(site)
        db.commit()
        load_scenario(db, site, "all")
        run_detection(db, site.website_id)
        run_anomaly_detection(db, site.website_id)
        run_correlation(db, site.website_id)
        print(json.dumps(summarize(db, site.website_id, run_risk_for_website(db, site.website_id)), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
