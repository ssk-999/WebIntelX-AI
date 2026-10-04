import pytest

from app.config import get_settings
from tests.test_api import ingest

SQLI = {"event_type": "http_request", "source": "app", "session_id": "s-sqli", "source_ip": "203.0.113.50", "method": "GET",
        "endpoint": "/products?id=1 UNION SELECT NULL,NULL--", "status_code": 500, "is_synthetic": True}


def wid(site):
    return site["website"]["website_id"]


def test_detection_endpoints_require_auth_and_isolate_accounts(client, auth_a, auth_b, site_a):
    w = wid(site_a)
    for method, path in [("post", f"/v1/websites/{w}/analyze"), ("get", f"/v1/websites/{w}/findings"),
                         ("get", f"/v1/websites/{w}/sessions"), ("get", f"/v1/websites/{w}/sessions/s1")]:
        assert getattr(client, method)(path).status_code == 401
        assert getattr(client, method)(path, headers=auth_b).status_code == 404         # existence not disclosed


def test_rule_catalogue_is_public_and_complete(client):
    body = client.get("/v1/detection/rules").json()
    ids = {r["rule_id"] for r in body["rules"]}
    assert body["config_status"] == "ok" and len(ids) == 13 and "R-AUTH-001" in ids
    r = next(r for r in body["rules"] if r["rule_id"] == "R-AUTH-001")
    assert r["thresholds"]["min_failures"] == 10 and r["mitre_reference"]["technique_id"] == "T1110" and "enabled" not in r["thresholds"]
    assert "not a probability" in body["note"]
    assert client.get("/health").json()["detection_config"] == "ok"


def test_auto_detection_on_ingest_creates_finding(client, auth_a, site_a):
    key = site_a["ingestion_key"]
    assert ingest(client, key, [SQLI]).status_code == 200
    fs = client.get(f"/v1/websites/{wid(site_a)}/findings", headers=auth_a).json()
    assert [f["rule_id"] for f in fs] == ["R-ATK-001"]
    f = fs[0]
    assert f["agent_name"] == "rule_engine" and f["finding_type"] == "attack_indicator" and f["event_timestamp"]
    assert f["evidence"]["interpretation"]["basis"] == "rule_template" and f["evidence"]["mitre_reference"]["technique_id"] == "T1190"
    assert client.get(f"/v1/websites/{wid(site_a)}/findings", params={"finding_type": "auth_anomaly"}, headers=auth_a).json() == []
    assert client.get(f"/v1/websites/{wid(site_a)}/findings", params={"min_confidence": 0.99}, headers=auth_a).json() == []
    assert len(client.get(f"/v1/websites/{wid(site_a)}/findings", params={"event_id": f["event_id"]}, headers=auth_a).json()) == 1
    assert client.get(f"/v1/websites/{wid(site_a)}/findings", params={"min_confidence": 2}, headers=auth_a).status_code == 422


def test_ingest_succeeds_even_if_detection_crashes(client, auth_a, site_a, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("detector exploded")
    monkeypatch.setattr("app.api.ingestion.run_detection_for_events", boom)
    r = ingest(client, site_a["ingestion_key"], [SQLI])
    assert r.status_code == 200 and r.json()["accepted"] == 1                 # telemetry never lost to a detection failure
    assert client.get(f"/v1/websites/{wid(site_a)}/events", headers=auth_a).json()[0]["endpoint"].startswith("/products")
    assert client.get(f"/v1/websites/{wid(site_a)}/findings", headers=auth_a).json() == []
    # ... and a later manual analysis recovers the finding
    monkeypatch.undo()
    assert client.post(f"/v1/websites/{wid(site_a)}/analyze", headers=auth_a).json()["findings_created"] == 1


def test_auto_detect_can_be_disabled(client, auth_a, site_a, monkeypatch):
    monkeypatch.setenv("AUTO_DETECT_ON_INGEST", "false")
    get_settings.cache_clear()
    try:
        ingest(client, site_a["ingestion_key"], [SQLI])
        assert client.get(f"/v1/websites/{wid(site_a)}/findings", headers=auth_a).json() == []
        assert client.post(f"/v1/websites/{wid(site_a)}/analyze", headers=auth_a).json()["findings_created"] == 1
    finally:
        monkeypatch.delenv("AUTO_DETECT_ON_INGEST")
        get_settings.cache_clear()


def test_findings_never_cross_accounts(client, auth_a, auth_b, site_a):
    r = client.post("/v1/websites", json={"domain": "other.example.org"}, headers=auth_b).json()
    ingest(client, site_a["ingestion_key"], [SQLI])
    ingest(client, r["ingestion_key"], [{**SQLI, "endpoint": "/q?x=<script>alert(1)</script>"}])
    a = client.get(f"/v1/websites/{wid(site_a)}/findings", headers=auth_a).json()
    b = client.get(f"/v1/websites/{r['website']['website_id']}/findings", headers=auth_b).json()
    assert [f["rule_id"] for f in a] == ["R-ATK-001"] and [f["rule_id"] for f in b] == ["R-ATK-002"]
    assert client.get(f"/v1/websites/{r['website']['website_id']}/findings", headers=auth_a).status_code == 404


def test_sessions_list_and_detail(client, auth_a, site_a):
    key = site_a["ingestion_key"]
    ingest(client, key, [SQLI, {"event_type": "page_view", "session_id": "s-calm", "source_ip": "203.0.113.51", "endpoint": "/", "is_synthetic": True},
                         {"event_type": "waf_alert", "source": "waf", "source_ip": "203.0.113.52", "endpoint": "/x", "is_synthetic": True}])
    w = wid(site_a)
    allr = client.get(f"/v1/websites/{w}/sessions", headers=auth_a).json()
    assert {s["key"] for s in allr} == {"s-sqli", "s-calm", "ip:203.0.113.52"}
    sus = client.get(f"/v1/websites/{w}/sessions", params={"suspicious_only": True, "sort": "findings"}, headers=auth_a).json()
    assert {s["key"] for s in sus} == {"s-sqli", "ip:203.0.113.52"} and all(s["finding_count"] >= 1 for s in sus)
    assert "event_ids" not in sus[0] and sus[0]["rule_ids"]
    d = client.get(f"/v1/websites/{w}/sessions/s-sqli", headers=auth_a).json()
    assert d["session"]["event_count"] == 1 and len(d["session"]["event_ids"]) == 1 and d["findings"][0]["rule_id"] == "R-ATK-001"
    inferred = client.get(f"/v1/websites/{w}/sessions/ip:203.0.113.52", headers=auth_a).json()
    assert inferred["session"]["inferred"] is True and inferred["findings"][0]["rule_id"] == "R-WAF-001"
    assert client.get(f"/v1/websites/{w}/sessions/nope", headers=auth_a).status_code == 404
    assert client.get(f"/v1/websites/{w}/sessions", params={"sort": "bogus"}, headers=auth_a).status_code == 422


def test_demo_load_runs_detection_by_default(client, auth_a, site_a):
    w = wid(site_a)
    r = client.post(f"/v1/websites/{w}/demo/load", json={"scenario": "injection_probe"}, headers=auth_a).json()
    assert r["detection"]["findings_created"] >= 9 and "R-ATK-005" in r["detection"]["by_rule"] and "labels" not in r
    r2 = client.post(f"/v1/websites/{w}/demo/load", json={"scenario": "bot_scraper", "analyze": False}, headers=auth_a).json()
    assert "detection" not in r2


@pytest.mark.parametrize("bad_batch", [[{"event_type": "page_view", "endpoint": "/" + "a" * 3000}]])
def test_invalid_events_do_not_reach_detection(client, auth_a, site_a, bad_batch):
    r = ingest(client, site_a["ingestion_key"], bad_batch).json()
    assert r["accepted"] == 0 and len(r["rejected"]) == 1
