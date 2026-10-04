"""Helpers for the anomaly-model tests.

They build light event stand-ins (the `EventLike` protocol from app/pipeline/sessionization.py) using the REAL
masking and feature-extraction functions, so the anomaly module is tested without FastAPI/SQLAlchemy. They bypass
only the pydantic validation/normalisation step of `process_event`; the DB/API path is covered in
tests/test_anomaly_api.py.
"""
from __future__ import annotations

import csv
import itertools
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from app.pipeline import masking
from app.pipeline.features import extract_features

T0 = datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc)
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
DATA_DIR = Path(__file__).resolve().parents[1] / "data"
_ids = itertools.count(1)


def make_event(event_type, ts, *, ip="198.51.100.1", sid="s", uid=None, ep=None, status=None, ua=BROWSER, attrs=None):
    endpoint = masking.mask_endpoint(ep) if ep else None
    attrs = masking.mask_value(attrs or {})
    feats = extract_features(event_type=event_type, endpoint=endpoint, status_code=status, user_agent=ua,
                             attributes=attrs, timestamp=ts)
    return SimpleNamespace(event_id=f"evt_{next(_ids):06d}", timestamp=ts, source_ip=ip, user_id=uid, session_id=sid,
                           event_type=event_type, features=feats)


def normal_session(rng: random.Random, i: int, start: datetime):
    """A plausible human browsing session: a few pages, gaps of 8-40 s, real interaction between pages."""
    evs, t = [], start
    for p in range(rng.randint(3, 8)):
        path = rng.choice(["/", "/products", "/products/3", "/about", "/cart", "/help"])
        evs.append(make_event("page_view", t, ip=f"192.0.2.{i % 250 + 1}", sid=f"sess-n{i}", ep=path, attrs={"page_seq": p + 1}))
        evs.append(make_event("interaction", t + timedelta(seconds=3), ip=f"192.0.2.{i % 250 + 1}", sid=f"sess-n{i}", ep=None,
                              attrs={"clicks": rng.randint(1, 4), "key_events": rng.randint(0, 6),
                                     "scroll_events": rng.randint(5, 30), "mouse_moves": rng.randint(50, 250)}))
        t += timedelta(seconds=rng.uniform(8, 40))
    return evs


def baseline_events(n_sessions: int = 80, seed: int = 7):
    rng = random.Random(seed)
    out = []
    for i in range(n_sessions):
        out += normal_session(rng, i, T0 + timedelta(seconds=rng.uniform(0, 3600)))
    return out


def attacker_events(sid="sess-attack", ip="203.0.113.99", failures=100, span_s=40):
    """A failed-login burst followed by sensitive requests, all in one session."""
    evs = [make_event("login_failure", T0 + timedelta(seconds=i * span_s / failures), ip=ip, sid=sid, uid=f"u-{i % 30}",
                      ep="/api/login", status=401) for i in range(failures)]
    evs += [make_event("sensitive_endpoint_access", T0 + timedelta(seconds=span_s + i), ip=ip, sid=sid, ep="/api/admin/users",
                       status=200) for i in range(5)]
    return evs


def load_demo_events():
    """All synthetic demo CSV rows as stand-ins + {session_key: (scenario, label)} ground truth (evaluation only)."""
    events, truth = [], {}
    for fn in ("normal_traffic.csv", "attack_scenarios.csv"):
        with (DATA_DIR / fn).open(newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                ts = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                status = int(r["status_code"]) if r["status_code"] else None
                ua = masking.mask_text(r["user_agent"]) if r["user_agent"] else None
                e = make_event(r["event_type"], ts, ip=r["source_ip"] or None, sid=r["session_id"] or None, uid=r["user_id"] or None,
                               ep=r["endpoint"] or None, status=status, ua=ua, attrs=json.loads(r["attributes"] or "{}"))
                events.append(e)
                truth[e.session_id or f"ip:{e.source_ip}"] = (r["scenario"], r["label"])
    return events, truth
