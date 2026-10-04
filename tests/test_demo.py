import csv
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.database import database
from app.database.models import Event, Website
from app.demo import generator
from app.demo.loader import ALL_ORDER, load_scenario
from app.pipeline.pipeline import EventRejected, process_event
from app.config import get_settings


def _rows(name):
    with (generator.DATA_DIR / name).open(newline="") as fh:
        return list(csv.DictReader(fh))


def test_generator_is_deterministic_and_matches_committed_files(tmp_path):
    generator.generate(tmp_path)
    for name in ("normal_traffic.csv", "attack_scenarios.csv", "sample_events.json"):
        assert (tmp_path / name).read_bytes() == (generator.DATA_DIR / name).read_bytes(), name


def test_only_documentation_ip_ranges_and_all_synthetic():
    rows = _rows("normal_traffic.csv") + _rows("attack_scenarios.csv")
    assert all(r["source_ip"].startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for r in rows)
    assert all(r["is_synthetic"] == "true" for r in rows)
    assert {r["label"] for r in rows} == {"benign", "malicious"}


def test_hero_scenario_structure():
    hero = [r for r in _rows("attack_scenarios.csv") if r["scenario"] == "hero_credential_abuse"]
    ts = lambda r: datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))  # noqa: E731
    fails = [r for r in hero if r["event_type"] == "login_failure"]
    assert len(fails) == 126 and (ts(fails[-1]) - ts(fails[0])).total_seconds() == pytest.approx(18, abs=0.01)
    assert {r["source_ip"] for r in hero} == {generator.ATTACKER_IP}
    order = [r["event_type"] for r in hero]
    first = {t: order.index(t) for t in ("page_view", "login_failure", "login_success", "session_created",
                                         "sensitive_endpoint_access", "http_request", "waf_alert")}
    assert list(first.values()) == sorted(first.values())          # chain is chronological
    assert order.count("login_success") == 1 and {r["user_id"] for r in fails[-3:]} == {generator.TARGET_ACCOUNT}
    pre = [r for r in hero if r["event_type"] == "page_view"]
    assert all(json.loads(r["attributes"])["webdriver"] is True for r in pre)
    # new session id after login differs from the pre-auth one
    assert next(r for r in hero if r["event_type"] == "session_created")["session_id"] != fails[0]["session_id"]


def test_benign_hard_negatives_exist():
    edge = [r for r in _rows("normal_traffic.csv") if r["scenario"] == "benign_failed_logins"]
    assert edge and all(r["label"] == "benign" for r in edge)


def test_every_row_passes_the_real_pipeline_and_sample_events_valid():
    site = Website(website_id="web_x", account_id="a", domain="d.com")
    for r in _rows("normal_traffic.csv")[:500] + _rows("attack_scenarios.csv"):
        try:
            process_event(generator.row_to_event(r), site, get_settings())
        except EventRejected as exc:  # pragma: no cover
            pytest.fail(f"{r['scenario']} row rejected: {exc.errors}")
    sample = json.loads((generator.DATA_DIR / "sample_events.json").read_text())["events"]
    assert len(sample) == 12
    for e in sample:
        process_event(e, site, get_settings())


def test_row_to_event_strips_ground_truth():
    ev = generator.row_to_event(_rows("attack_scenarios.csv")[0])
    assert "scenario" not in ev and "label" not in ev and ev["is_synthetic"] is True


def test_loader_shifts_time_marks_synthetic_and_returns_labels(client, auth_a, site_a):
    wid = site_a["website"]["website_id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        site = db.get(Website, wid)
        res = load_scenario(db, site, "hero_credential_abuse", now=now)
        assert res["loaded"] == 144 and res["rejected"] == 0
        end = datetime.fromisoformat(res["window_end"])
        assert abs((now - end).total_seconds() - 20) < 1
        assert set(v["label"] for v in res["labels"].values()) == {"malicious"}
        assert len(res["labels"]) == res["loaded"] == 144          # one label per event (regression: ids were None)
        assert db.scalar(select(func.count()).select_from(Event).where(Event.is_synthetic.is_(False))) == 0
        stored = db.scalars(select(Event).where(Event.event_type == "login_failure")).all()
        # M3: feature extraction now populates `features` at ingestion (was None in M2)
        assert len(stored) == 126 and all(e.features and e.features["v"] == 1 for e in stored)


def test_loader_all_and_unknown(client, auth_a, site_a):
    wid = site_a["website"]["website_id"]
    with database.SessionLocal() as db:
        site = db.get(Website, wid)
        res = load_scenario(db, site, "all")
        assert res["loaded"] == 9063 + 455 and res["rejected"] == 0
        assert [p["scenario"] for p in res["parts"]] == ALL_ORDER
        with pytest.raises(ValueError):
            load_scenario(db, site, "nope")


def test_demo_api_owner_only_and_flag(client, auth_a, auth_b, site_a, monkeypatch):
    wid = site_a["website"]["website_id"]
    assert client.get("/v1/demo/scenarios").json()["scenarios"][0] == "all"
    assert client.post(f"/v1/websites/{wid}/demo/load", json={"scenario": "bot_scraper"}, headers=auth_b).status_code == 404
    assert client.post(f"/v1/websites/{wid}/demo/load", json={"scenario": "nope"}, headers=auth_a).status_code == 422
    r = client.post(f"/v1/websites/{wid}/demo/load", json={"scenario": "injection_probe"}, headers=auth_a)
    assert r.status_code == 200 and r.json()["loaded"] == 11 and r.json()["synthetic"] is True and "labels" not in r.json()
    assert client.get(f"/v1/websites/{wid}/verification", headers=auth_a).json()["status"] == "active"
    monkeypatch.setenv("ENABLE_DEMO_LOADER", "false")
    get_settings.cache_clear()
    try:
        assert client.post(f"/v1/websites/{wid}/demo/load", json={}, headers=auth_a).status_code == 403
    finally:
        monkeypatch.delenv("ENABLE_DEMO_LOADER")
        get_settings.cache_clear()
