"""Loads the synthetic demo datasets into a website through the SAME validate/normalise/mask
pipeline that real telemetry uses. Every loaded event is forced to is_synthetic=True.

Timestamps are shifted so each scenario ends at a chosen offset before 'now' (demo looks live).
Ground-truth labels are returned for evaluation only; they are never stored with the events.
"""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.models import Website
from app.demo.generator import DATA_DIR, row_to_event
from app.pipeline.pipeline import EventRejected, process_event

# scenario groups -> (source csv, scenarios in it, how long before now the group's last event lands)
GROUPS: dict[str, tuple[str, tuple[str, ...], timedelta]] = {
    "normal": ("normal_traffic.csv", ("normal_traffic", "benign_failed_logins"), timedelta(minutes=5)),
    "hero_credential_abuse": ("attack_scenarios.csv", ("hero_credential_abuse",), timedelta(seconds=20)),
    "injection_probe": ("attack_scenarios.csv", ("injection_probe",), timedelta(minutes=2)),
    "bot_scraper": ("attack_scenarios.csv", ("bot_scraper",), timedelta(seconds=90)),
}
ALL_ORDER = ["normal", "bot_scraper", "injection_probe", "hero_credential_abuse"]


def available_scenarios() -> list[str]:
    return ["all", *ALL_ORDER]


def _read(csv_name: str, scenarios: tuple[str, ...], data_dir: Path) -> list[dict]:
    with (data_dir / csv_name).open(newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r["scenario"] in scenarios]


def load_scenario(db: Session, site: Website, name: str, now: datetime | None = None,
                  data_dir: Path = DATA_DIR, commit: bool = True) -> dict:
    if name == "all":
        out = {"scenario": "all", "loaded": 0, "rejected": 0, "labels": {}, "parts": []}
        for part in ALL_ORDER:
            r = load_scenario(db, site, part, now=now, data_dir=data_dir, commit=commit)
            out["loaded"] += r["loaded"]
            out["rejected"] += r["rejected"]
            out["labels"].update(r["labels"])
            out["parts"].append({k: r[k] for k in ("scenario", "loaded", "rejected", "window_start", "window_end")})
        return out
    if name not in GROUPS:
        raise ValueError(f"unknown scenario '{name}'; choose one of {available_scenarios()}")

    csv_name, scenarios, end_offset = GROUPS[name]
    rows = _read(csv_name, scenarios, data_dir)
    if not rows:
        raise FileNotFoundError(f"no rows for scenario '{name}' in {csv_name}; run `python -m app.demo.generator`")
    now = now or datetime.now(timezone.utc)
    parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
    last = max(parse(r["timestamp"]) for r in rows)
    delta = (now - end_offset) - last

    settings, events, labels, rejected = get_settings(), [], {}, 0
    for row in rows:
        payload = row_to_event(row)
        payload["timestamp"] = (parse(row["timestamp"]) + delta).isoformat()
        payload["is_synthetic"] = True
        try:
            ev = process_event(payload, site, settings, now=now)
        except EventRejected:
            rejected += 1
            continue
        events.append(ev)
        labels[ev.event_id] = {"scenario": row["scenario"], "label": row["label"]}
    db.add_all(events)
    if commit:
        db.commit()
    times = [e.timestamp for e in events]
    return {
        "scenario": name, "loaded": len(events), "rejected": rejected, "labels": labels,
        "window_start": min(times).isoformat() if times else None,
        "window_end": max(times).isoformat() if times else None,
    }


def main() -> None:  # pragma: no cover
    import argparse

    from app.database import database

    ap = argparse.ArgumentParser(description="Load synthetic demo events into a website")
    ap.add_argument("--website-id", required=True)
    ap.add_argument("--scenario", default="all", choices=available_scenarios())
    args = ap.parse_args()
    database.init_db()
    with database.SessionLocal() as db:
        site = db.get(Website, args.website_id)
        if site is None:
            raise SystemExit("website not found")
        res = load_scenario(db, site, args.scenario)
        res.pop("labels")
        print(res)


if __name__ == "__main__":  # pragma: no cover
    main()
