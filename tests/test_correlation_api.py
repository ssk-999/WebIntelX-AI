"""API + persistence tests for correlation, timeline and graph (AC-09, AC-12, AC-13, AC-22)."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.correlation.engine import run_correlation
from app.database import database
from app.database.models import Correlation, Feedback, Finding, Incident
from tests.test_api import ingest

HERO_TOTAL = 144


def wid(site):
    return site["website"]["website_id"]


def load(client, auth, site, scenario):
    r = client.post(f"/v1/websites/{wid(site)}/demo/load", json={"scenario": scenario}, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def incidents(client, auth, site):
    return client.get(f"/v1/websites/{wid(site)}/incidents", headers=auth).json()


@pytest.fixture
def hero_incident(client, auth_a, site_a):
    load(client, auth_a, site_a, "hero_credential_abuse")
    incs = incidents(client, auth_a, site_a)
    assert len(incs) == 1
    return incs[0]


def test_demo_load_creates_incident_candidates_without_risk(client, auth_a, site_a, monkeypatch):
    # Correlation itself never assigns risk. Since M7 the demo loader runs a separate scoring step; switch it off here
    # so this test keeps proving that correlation alone creates DETECTED candidates with no risk (scoring: tests/test_risk_api.py).
    monkeypatch.setattr("app.api.demo.run_risk_for_website", lambda *a, **k: {})
    r = load(client, auth_a, site_a, "all")
    corr = r["correlation"]
    assert corr["status"] == "ok" and corr["clusters"] == 3 and corr["potential_incidents"] == 3 and corr["incidents_created"] == 3
    incs = incidents(client, auth_a, site_a)
    assert len(incs) == 3 and {i["status"] for i in incs} == {"DETECTED"}
    assert all(i["risk_level"] is None and i["risk_score"] is None and i["confidence"] is None for i in incs)   # risk comes from the separate M7 scoring step
    assert "Risk has not been scored yet" in " ".join(incs[0]["details"]["limitations"])


def test_benign_traffic_creates_no_incident(client, auth_a, site_a):
    load(client, auth_a, site_a, "normal")                             # 9,063 events incl. 8 mistyped-password users
    assert incidents(client, auth_a, site_a) == []
    out = client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).json()
    assert out["status"] == "no_findings" and out["clusters"] == 0 and out["correlation_records"] == 0


def test_hero_incident_contains_every_hero_event_and_all_six_stages(hero_incident):
    d = hero_incident["details"]
    assert d["event_count"] == HERO_TOTAL and len(d["event_ids"]) == HERO_TOTAL
    assert list(d["stages"]) == ["abnormal_navigation", "credential_attack", "authentication_success",
                                 "new_session", "sensitive_access", "attack_indicator"]
    assert d["stages"]["credential_attack"]["event_count"] == 126
    assert d["entities"]["source_ips"] == ["203.0.113.77"] and d["entities"]["session_ids"] == ["sess-h-auth", "sess-h-pre"]
    assert "/api/admin/customers/export" in d["affected_resources"] and all("?" not in p for p in d["affected_resources"])
    assert hero_incident["title"].startswith("Suspicious activity chain from 203.0.113.77")


def test_post_login_events_are_correlated_even_without_the_ml_or_automation_rule(client, auth_a, site_a, monkeypatch):
    """README (M3) deferred the post-login events to correlation: with only rules (no ML, automation rule off) the
    hero chain was 139/144 flagged. Correlation must still bring in the remaining events by IP/session/user."""
    from app.detection.config import DetectionConfig, get_detection_config
    cfg = get_detection_config()
    data = {**cfg.data, "rules": {**cfg.data["rules"], "R-BEH-002": {**cfg.data["rules"]["R-BEH-002"], "enabled": False}}}
    monkeypatch.setattr("app.detection.engine.get_detection_config", lambda: DetectionConfig(data=data))
    r = load(client, auth_a, site_a, "hero_credential_abuse")
    assert r["detection"]["suspicious_events"] < HERO_TOTAL            # rules alone do not flag everything
    assert incidents(client, auth_a, site_a)[0]["details"]["event_count"] == HERO_TOTAL


def test_correlation_records_follow_the_prd_shape(client, auth_a, hero_incident):
    body = client.get(f"/v1/incidents/{hero_incident['incident_id']}/correlations", headers=auth_a).json()
    assert body["count"] == sum(body["by_type"].values()) > 0
    assert {"same_ip", "same_session", "same_user", "same_endpoint", "attack_sequence"} <= set(body["by_type"])
    ids = set(hero_incident["details"]["event_ids"])
    for c in body["correlations"]:
        assert c["event_id"] in ids and c["related_event_id"] in ids and 0 <= c["strength"] <= 1
        assert set(c) == {"correlation_id", "event_id", "related_event_id", "relationship_type", "strength"}
    only = client.get(f"/v1/incidents/{hero_incident['incident_id']}/correlations", params={"relationship_type": "attack_sequence"}, headers=auth_a).json()
    assert only["count"] == 4 and {c["relationship_type"] for c in only["correlations"]} == {"attack_sequence"}


def test_timeline_is_chronological_labelled_and_traceable(client, auth_a, hero_incident):
    body = client.get(f"/v1/incidents/{hero_incident['incident_id']}/timeline", headers=auth_a).json()
    tl, ids = body["timeline"], set(hero_incident["details"]["event_ids"])
    ts = [e["timestamp"] for e in tl[:-1]]
    assert ts == sorted(ts) and tl[-1]["label"] == "Incident correlated" and tl[-1]["evidence_type"] == "system"
    assert {e["evidence_type"] for e in tl} == {"observed", "derived_indicator", "system"}
    burst = next(e for e in tl if e.get("event_type") == "login_failure")
    assert burst["event_count"] == 126 and burst["label"].startswith("126 failed login attempts") and "credential_attack" in burst["stages"]
    assert next(e for e in tl if e.get("event_type") == "login_success")["label"].startswith("Successful login for account acct-4821")
    for e in tl:
        assert set(e["event_ids"]) <= ids and len(e["event_ids"]) <= 50 and (e["event_ids_truncated"] == (e["event_count"] > 50))
    assert [e["entry_id"] for e in tl] == [f"tl_{n:03d}" for n in range(1, len(tl) + 1)]
    det = [e for e in tl if e["kind"] == "detection"]
    assert det and all("not a probability" in e["note"] for e in det)


def test_labels_never_contain_query_strings_or_payloads(client, auth_a, hero_incident):
    tl = client.get(f"/v1/incidents/{hero_incident['incident_id']}/timeline", headers=auth_a).json()["timeline"]
    observed = [e["label"] for e in tl if e["kind"] == "observed"]
    assert not any("UNION" in l or "SELECT" in l or "?" in l for l in observed)


def test_graph_nodes_and_edges_trace_to_incident_events(client, auth_a, hero_incident):
    g = client.get(f"/v1/incidents/{hero_incident['incident_id']}/graph", headers=auth_a).json()
    ids, nodes = set(hero_incident["details"]["event_ids"]), {n["id"] for n in g["nodes"]}
    assert g["node_count"] == len(g["nodes"]) and g["edge_count"] == len(g["edges"])
    types = {n["type"] for n in g["nodes"]}
    assert types == {"source_ip", "session", "event_group", "incident"}
    for n in g["nodes"]:
        assert set(n["event_ids"]) <= ids
    for e in g["edges"]:
        assert e["source"] in nodes and e["target"] in nodes and set(e["event_ids"]) <= ids and e["evidence_type"]
    assert sum(1 for n in g["nodes"] if n["type"] == "incident") == 1
    assert {e["relationship"] for e in g["edges"]} >= {"used_session", "began_with", "followed_by", "evidence_for"}
    assert any(e["correlation_type"] == "attack_sequence" for e in g["edges"] if e["relationship"] == "followed_by")
    # graph is a DAG in layer order (suitable for a left-to-right layout)
    layer = {n["id"]: n["layer"] for n in g["nodes"]}
    assert all(layer[e["source"]] <= layer[e["target"]] for e in g["edges"])
    assert g["nodes"][0]["type"] == "source_ip" and "not proof" in g["note"]


def test_rerun_is_idempotent_and_keeps_incident_identity(client, auth_a, site_a, hero_incident):
    first = client.get(f"/v1/incidents/{hero_incident['incident_id']}/correlations", headers=auth_a).json()
    r = client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).json()
    assert r["incidents_created"] == 0 and r["incidents_updated"] == 1 and r["incidents_removed"] == 0
    again = client.get(f"/v1/incidents/{hero_incident['incident_id']}/correlations", headers=auth_a).json()
    assert again["count"] == first["count"]
    assert [i["incident_id"] for i in incidents(client, auth_a, site_a)] == [hero_incident["incident_id"]]
    with database.SessionLocal() as db:
        assert db.scalar(select(func.count(Correlation.correlation_id))) == first["count"]       # no duplicates


def test_incident_cluster_grows_with_new_events_but_keeps_id_status_and_risk(client, auth_a, site_a):
    key = site_a["ingestion_key"]
    now = datetime.now(timezone.utc)
    burst = [{"event_type": "login_failure", "source": "auth", "session_id": "s-a", "source_ip": "203.0.113.90", "method": "POST",
              "endpoint": "/api/login", "status_code": 401, "user_id": f"x{i % 6}", "is_synthetic": True,
              "timestamp": (now - timedelta(seconds=120 - i)).isoformat()} for i in range(12)]
    for i in range(0, 12, 10):
        assert ingest(client, key, burst[i:i + 10]).status_code == 200
    assert client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).json()["incidents_created"] == 1
    inc = incidents(client, auth_a, site_a)[0]
    with database.SessionLocal() as db:                                  # a later milestone / analyst touches the incident
        row = db.get(Incident, inc["incident_id"])
        row.status, row.risk_level, row.risk_score = "INVESTIGATING", "HIGH", 82.0
        row.details = {**row.details, "risk_factors": ["kept"]}
        db.commit()
    more = [{"event_type": "login_success", "source": "auth", "session_id": "s-a", "source_ip": "203.0.113.90", "user_id": "x1",
             "endpoint": "/api/login", "status_code": 200, "method": "POST", "is_synthetic": True, "timestamp": (now - timedelta(seconds=60)).isoformat()}]
    assert ingest(client, key, more).status_code == 200
    r = client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).json()
    assert r["incidents_created"] == 0 and r["incidents_updated"] == 1
    after = incidents(client, auth_a, site_a)[0]
    assert after["incident_id"] == inc["incident_id"] and after["details"]["event_count"] == inc["details"]["event_count"] + 1
    assert (after["status"], after["risk_level"], after["risk_score"]) == ("INVESTIGATING", "HIGH", 82.0)
    assert after["details"]["risk_factors"] == ["kept"]                  # keys owned by later milestones survive


def test_vanished_cluster_removes_untouched_incident_but_keeps_one_with_feedback(client, auth_a, site_a):
    load(client, auth_a, site_a, "all")
    by_title = {i["title"]: i for i in incidents(client, auth_a, site_a)}
    hero = next(i for t, i in by_title.items() if t.startswith("Suspicious activity chain"))
    probe = next(i for t, i in by_title.items() if t.startswith("Multi-vector"))
    with database.SessionLocal() as db:
        db.add(Feedback(incident_id=probe["incident_id"], analyst_decision="FALSE_POSITIVE", comment="test"))
        db.commit()
        for inc_id in (hero["incident_id"], probe["incident_id"]):
            ids = db.get(Incident, inc_id).details["event_ids"]
            for i in range(0, len(ids), 500):
                for f in db.scalars(select(Finding).where(Finding.event_id.in_(ids[i:i + 500]))):
                    db.delete(f)
        db.commit()
    r = client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).json()
    assert r["incidents_removed"] == 1 and r["incidents_stale"] == 1
    left = {i["incident_id"]: i for i in incidents(client, auth_a, site_a)}
    assert hero["incident_id"] not in left                               # untouched -> removed with its correlations
    assert left[probe["incident_id"]]["details"]["stale"] is True        # has analyst feedback -> preserved, flagged
    with database.SessionLocal() as db:
        owners = set(db.scalars(select(Correlation.incident_id)))
        assert hero["incident_id"] not in owners and probe["incident_id"] in owners


def test_isolation_between_accounts(client, auth_a, auth_b, site_a, hero_incident):
    iid = hero_incident["incident_id"]
    for suffix in ("correlations", "timeline", "graph"):
        assert client.get(f"/v1/incidents/{iid}/{suffix}").status_code == 401
        assert client.get(f"/v1/incidents/{iid}/{suffix}", headers=auth_b).status_code == 404
    assert client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_b).status_code == 404
    site_b = client.post("/v1/websites", json={"domain": "other.example.org"}, headers=auth_b).json()
    r = client.post(f"/v1/websites/{wid(site_b)}/correlate", headers=auth_b).json()
    assert r["clusters"] == 0 and incidents(client, auth_b, site_b) == []       # A's attack never leaks into B


def test_correlation_never_mixes_two_websites_events(client, auth_a, auth_b, site_a):
    """Same attacker IP + session id on two different websites must produce two separate incidents."""
    site_b = client.post("/v1/websites", json={"domain": "other.example.org"}, headers=auth_b).json()
    load(client, auth_a, site_a, "hero_credential_abuse")
    load(client, auth_b, site_b, "hero_credential_abuse")
    a, b = incidents(client, auth_a, site_a), incidents(client, auth_b, site_b)
    assert len(a) == len(b) == 1 and a[0]["details"]["event_count"] == b[0]["details"]["event_count"] == HERO_TOTAL
    assert not set(a[0]["details"]["event_ids"]) & set(b[0]["details"]["event_ids"])


def test_failure_is_contained_and_writes_nothing(client, auth_a, site_a, monkeypatch):
    load(client, auth_a, site_a, "injection_probe")
    with database.SessionLocal() as db:
        before = db.scalar(select(func.count(Correlation.correlation_id)))
    def boom(*a, **k):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr("app.correlation.engine.correlate", boom)
    r = client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a)
    assert r.status_code == 200 and r.json()["status"] == "error" and r.json()["error"] == "RuntimeError"
    with database.SessionLocal() as db:
        assert db.scalar(select(func.count(Correlation.correlation_id))) == before
    assert len(incidents(client, auth_a, site_a)) == 1                   # existing incident untouched


def test_disabled_config_is_reported_not_crashed(client, auth_a, site_a, monkeypatch):
    from app.correlation.config import CorrelationConfig, defaults
    cfg = defaults()
    cfg.data["enabled"] = False
    with database.SessionLocal() as db:
        assert run_correlation(db, wid(site_a), cfg=cfg).status == "disabled"


def test_config_endpoint_and_health(client, monkeypatch):
    body = client.get("/v1/correlation/config").json()
    assert body["config"]["status"] == "ok" and "attack_sequence" in body["config"]["base_strength"] and "not a probability" in body["note"]
    assert client.get("/health").json()["correlation_config"] == "ok"


def test_bad_config_file_falls_back_and_is_reported(tmp_path):
    from app.correlation.config import load_config
    bad = tmp_path / "c.yaml"
    bad.write_text("merge_types: [bogus]\n")
    cfg = load_config(str(bad))
    assert cfg.status == "fallback_defaults" and "merge_types" in cfg.error and cfg["merge_types"][0] == "same_ip"
    assert load_config(str(tmp_path / "missing.yaml")).status == "fallback_defaults"


def test_correlating_an_empty_website_is_a_clean_noop(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).json()
    assert r["status"] == "no_findings" and r["events_considered"] == 0
