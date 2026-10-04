"""Offline evaluation against the synthetic ground-truth labels (PRD section 39: precision/recall/F1).

HONESTY NOTE: the rules and thresholds were developed while looking at this same synthetic dataset, so
these numbers show the pipeline behaves as designed on controlled data; they are NOT evidence of
real-world accuracy. Event-level recall is expected to be < 1 at this milestone: events that are only
malicious by context (e.g. the post-login API calls of the hero chain) are linked later by the
correlation engine (milestone 5), not by single-source rules.

Run:  python -m app.detection.evaluation
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event, Finding


def flagged_event_ids(db: Session, website_id: str) -> tuple[set[str], set[str], dict[str, set[str]]]:
    """(anchors, anchors+evidence, event_id -> rule ids) for all findings of the website."""
    anchors, flagged, rules = set(), set(), defaultdict(set)
    q = select(Finding).join(Event, Event.event_id == Finding.event_id).where(Event.website_id == website_id)
    for f in db.scalars(q):
        ev = f.evidence or {}
        anchors.add(f.event_id)
        flagged.add(f.event_id)
        flagged.update(ev.get("event_ids", []))
        rules[f.event_id].add(ev.get("rule_id", "?"))
    return anchors, flagged, rules


def evaluate_against_labels(db: Session, website_id: str, labels: dict[str, dict]) -> dict:
    anchors, flagged, rules = flagged_event_ids(db, website_id)
    mal = {e for e, v in labels.items() if v["label"] == "malicious"}
    ben = set(labels) - mal
    tp, fp, fn = len(flagged & mal), len(flagged & ben), len(mal - flagged)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    per: dict[str, dict] = {}
    by_sc: dict[str, list[str]] = defaultdict(list)
    for e, v in labels.items():
        by_sc[v["scenario"]].append(e)
    for sc, ids in sorted(by_sc.items()):
        s = set(ids)
        per[sc] = {"events": len(s), "flagged": len(s & flagged), "has_finding": bool(s & anchors),
                   "label": labels[ids[0]]["label"]}
    return {
        "labeled_events": len(labels), "malicious": len(mal), "benign": len(ben),
        "true_positive": tp, "false_positive": fp, "false_negative": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "scenarios": per,
        "false_positive_examples": [{"event_id": e, "rules": sorted(rules.get(e, []))} for e in sorted(flagged & ben)[:5]],
        "caveat": "Synthetic data; rules were tuned on the same data. Not a real-world accuracy claim.",
    }


def main() -> None:  # pragma: no cover
    import json

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import models
    from app.database.database import Base
    from app.demo.loader import load_scenario
    from app.detection.engine import run_detection

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
        det = run_detection(db, site.website_id)
        print(json.dumps({"detection": det.to_dict(), "evaluation": evaluate_against_labels(db, site.website_id, loaded["labels"])}, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
