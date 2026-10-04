"""Offline evaluation of the anomaly model against the synthetic ground-truth labels (PRD section 39).

Unit of evaluation is the SESSION (the model's unit of analysis), not the event.

HONESTY NOTE: thresholds were chosen while looking at this same synthetic data, so these numbers show the
model behaves as designed on controlled data; they are NOT evidence of real-world accuracy. Low-volume attack
sessions are expected to be missed by design (see README): they are the job of the attack-indicator rules.

Run:  python -m app.ml.evaluation      (loads ALL demo data into a throw-away in-memory DB)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

from app.ml.anomaly_model import AnomalyReport


def evaluate_sessions(report: AnomalyReport, truth: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    """`truth`: session_key -> {"label": "malicious"|"benign", "scenario": str}."""
    flagged = set(report.flagged_sessions)
    scored = {s.key: s for s in report.scores}
    keys = [k for k in truth if k in scored]
    mal = {k for k in keys if truth[k]["label"] == "malicious"}
    ben = set(keys) - mal
    tp, fp, fn = len(flagged & mal), len(flagged & ben), len(mal - flagged)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    per: dict[str, dict] = defaultdict(lambda: {"sessions": 0, "flagged": 0})
    for k in keys:
        if truth[k]["label"] == "malicious":
            sc = per[truth[k]["scenario"]]
            sc["sessions"] += 1
            sc["flagged"] += k in flagged
    return {
        "status": report.status, "sessions_evaluated": len(keys), "malicious_sessions": len(mal), "benign_sessions": len(ben),
        "true_positive": tp, "false_positive": fp, "false_negative": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "malicious_scenarios": dict(sorted(per.items())),
        "missed_malicious_sessions": sorted(mal - flagged),
        "false_positive_examples": sorted(flagged & ben)[:5],
        "caveat": "Synthetic data; thresholds were tuned on the same data. Not a real-world accuracy claim.",
    }


def main() -> None:  # pragma: no cover
    import json

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import models
    from app.database.database import Base
    from app.demo.loader import load_scenario
    from app.detection.engine import load_events
    from app.ml.engine import run_anomaly_detection
    from app.pipeline.sessionization import session_key

    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    with sessionmaker(bind=eng, expire_on_commit=False)() as db:
        acc = models.Account(email="eval@example.com", password_hash="x")
        db.add(acc)
        db.flush()
        site = models.Website(account_id=acc.account_id, domain="eval.example.com")
        db.add(site)
        db.commit()
        loaded = load_scenario(db, site, "all")
        report = run_anomaly_detection(db, site.website_id)
        truth: dict[str, dict] = {}
        for e in load_events(db, site.website_id):
            lab = loaded["labels"].get(e.event_id)
            if lab:
                k = session_key(e)[0]
                if k not in truth or lab["label"] == "malicious":      # a session is malicious if any of its events is
                    truth[k] = lab
        print(json.dumps({"anomaly": report.to_dict(top_n=5), "evaluation": evaluate_sessions(report, truth)}, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
