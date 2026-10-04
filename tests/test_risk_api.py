"""API tests for risk scoring (FR-19, AC-16, AC-22)."""
from dataclasses import replace

import pytest

from app.config import get_settings
from app.risk import scoring as R
from app.risk.config import RiskConfig, defaults
from app.threat_intel import service as S


def wid(site):
    return site["website"]["website_id"]


@pytest.fixture
def hero(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a)
    assert r.status_code == 200, r.text
    incs = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()
    assert len(incs) == 1
    return incs[0]["incident_id"]


def risk(client, auth, iid):
    return client.get(f"/v1/incidents/{iid}/risk", headers=auth)


def test_config_endpoint_is_public_and_health_reports_it(client):
    r = client.get("/v1/risk/config")
    assert r.status_code == 200
    body = r.json()["config"]
    assert body["weights"]["authentication"] == 20 and body["status"] == "ok" and len(body["fingerprint"]) == 12
    h = client.get("/health").json()
    assert h["risk_config"] == "ok" and h["version"].startswith("0.")


def test_requires_authentication(client, hero):
    assert client.post(f"/v1/incidents/{hero}/risk").status_code == 401
    assert client.get(f"/v1/incidents/{hero}/risk").status_code == 401
    assert client.post("/v1/websites/web_x/risk/score").status_code == 401


def test_demo_load_scores_the_hero_incident(client, auth_a, site_a, hero):
    r = risk(client, auth_a, hero)
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "ok" and j["risk_level"] in ("HIGH", "CRITICAL") and j["stale"] is False
    assert j["basis"] == "config_driven_scoring" and j["contains_synthetic_data"] is True
    assert {f["factor"] for f in j["factors"]} == set(defaults()["weights"])
    assert all(f["basis"] for f in j["factors"])
    inc = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    assert (inc["risk_level"], inc["risk_score"], inc["confidence"]) == (j["risk_level"], j["risk_score"], j["confidence"])
    assert inc["status"] == "DETECTED"                       # scoring never changes the lifecycle
    assert inc["details"]["risk"]["risk_score"] == j["risk_score"]


def test_demo_load_response_contains_risk_summary(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a).json()
    assert r["risk"]["scored"] == 1 and r["risk"]["high_risk"] == 1 and r["risk"]["by_level"]


def test_rescoring_is_idempotent(client, auth_a, hero):
    a = client.post(f"/v1/incidents/{hero}/risk", headers=auth_a).json()
    b = client.post(f"/v1/incidents/{hero}/risk", headers=auth_a).json()
    assert a["risk_score"] == b["risk_score"] and a["confidence"] == b["confidence"] and a["factors"] == b["factors"]


def test_unscored_incident_reports_not_run(client, auth_a, site_a, monkeypatch):
    monkeypatch.setattr("app.api.demo.run_risk_for_website", lambda *a, **k: {})
    client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a)
    iid = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()[0]["incident_id"]
    assert risk(client, auth_a, iid).json()["status"] == "not_run"
    inc = client.get(f"/v1/incidents/{iid}", headers=auth_a).json()
    assert inc["risk_level"] is None and inc["risk_score"] is None


def test_isolation_between_customers(client, auth_a, auth_b, hero):
    assert client.post(f"/v1/incidents/{hero}/risk", headers=auth_b).status_code == 404
    assert risk(client, auth_b, hero).status_code == 404
    site_b = client.post("/v1/websites", json={"domain": "other.example.com"}, headers=auth_b).json()
    assert client.post(f"/v1/websites/{wid(site_b)}/risk/score", headers=auth_b).json()["incidents"] == 0
    # B cannot score A's website
    site_a_id = client.get("/v1/websites", headers=auth_a).json()[0]["website_id"]
    assert client.post(f"/v1/websites/{site_a_id}/risk/score", headers=auth_b).status_code == 404


def test_unknown_incident_is_404(client, auth_a):
    assert client.post("/v1/incidents/inc_nope/risk", headers=auth_a).status_code == 404


def _use_synthetic_ti(monkeypatch):
    s = replace(get_settings(), ti_provider="synthetic_demo", ti_api_key="")
    monkeypatch.setattr(S, "get_settings", lambda: s)
    import app.api.threat_intel as api
    monkeypatch.setattr(api, "get_settings", lambda: s)

    def no_net():
        raise AssertionError("real HTTP client requested in a test")
    monkeypatch.setattr(S, "make_client", no_net)


def test_synthetic_threat_intel_is_excluded_and_marks_score_stale(client, auth_a, hero, monkeypatch):
    _use_synthetic_ti(monkeypatch)
    before = risk(client, auth_a, hero).json()
    assert next(f for f in before["factors"] if f["factor"] == "threat_intel")["status"] == "not_assessed"
    enr = client.post(f"/v1/incidents/{hero}/threat-intel", headers=auth_a).json()
    assert enr["contains_synthetic"] is True
    stale = risk(client, auth_a, hero).json()
    assert stale["stale"] is True and "threat-intelligence report changed" in stale["stale_reasons"][0]
    after = client.post(f"/v1/incidents/{hero}/risk", headers=auth_a).json()
    ti = next(f for f in after["factors"] if f["factor"] == "threat_intel")
    assert after["stale"] is False and ti["status"] == "excluded" and ti["points"] == 0
    assert after["risk_score"] == before["risk_score"]       # synthetic intelligence never raises real severity
    assert risk(client, auth_a, hero).json()["stale"] is False


def test_correlation_rerun_preserves_the_stored_risk(client, auth_a, site_a, hero):
    before = risk(client, auth_a, hero).json()
    assert client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).status_code == 200
    after = risk(client, auth_a, hero).json()
    assert after["status"] == "ok" and after["risk_score"] == before["risk_score"] and after["stale"] is False
    inc = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    assert inc["risk_level"] == before["risk_level"]


def test_scoring_failure_is_controlled_and_writes_nothing(client, auth_a, site_a, monkeypatch):
    monkeypatch.setattr("app.api.demo.run_risk_for_website", lambda *a, **k: {})
    client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a)
    iid = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()[0]["incident_id"]

    def boom(*a, **k):
        raise RuntimeError("secret detail")
    monkeypatch.setattr(R, "gather_inputs", boom)
    r = client.post(f"/v1/incidents/{iid}/risk", headers=auth_a)
    assert r.status_code == 200 and r.json()["status"] == "error" and "secret detail" not in r.text
    assert client.get(f"/v1/incidents/{iid}", headers=auth_a).json()["risk_level"] is None


def test_disabled_config_writes_nothing(client, auth_a, site_a, monkeypatch):
    monkeypatch.setattr("app.api.demo.run_risk_for_website", lambda *a, **k: {})
    client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a)
    iid = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()[0]["incident_id"]
    off = RiskConfig(data={**defaults().data, "enabled": False})
    monkeypatch.setattr(R, "get_risk_config", lambda: off)
    assert client.post(f"/v1/incidents/{iid}/risk", headers=auth_a).json()["status"] == "disabled"
    assert client.get(f"/v1/incidents/{iid}", headers=auth_a).json()["risk_level"] is None


def test_website_summary_listing_filter_and_sort(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "all"}, headers=auth_a)
    assert r.status_code == 200
    summary = r.json()["risk"]
    assert summary["incidents"] == 3 and summary["scored"] == 3 and summary["high_risk"] == 1
    scores = [d["risk_score"] for d in summary["incidents_detail"]]
    assert scores == sorted(scores, reverse=True)
    again = client.post(f"/v1/websites/{wid(site_a)}/risk/score", headers=auth_a).json()
    assert again["by_level"] == summary["by_level"]
    base = f"/v1/websites/{wid(site_a)}/incidents"
    top = client.get(base + "?sort=risk", headers=auth_a).json()
    assert [i["risk_score"] for i in top] == scores
    high = client.get(base + "?risk_level=high", headers=auth_a).json()
    assert len(high) == 1 and high[0]["risk_level"] == "HIGH" and high[0]["incident_id"] == top[0]["incident_id"]
    assert client.get(base + "?risk_level=HIGH", headers=auth_a).status_code == 200
    assert client.get(base + "?risk_level=bogus", headers=auth_a).status_code == 422
    assert client.get(base + "?sort=bogus", headers=auth_a).status_code == 422
    assert len(client.get(base, headers=auth_a).json()) == 3                 # default listing is unchanged
    # the isolated injection probe and the scraper carry LOW risk; the hero chain must outrank both
    assert top[0]["risk_score"] > top[1]["risk_score"] >= top[2]["risk_score"]
    for i in top:                                                            # every score is explained by its factors
        assert abs(sum(f["points"] for f in i["details"]["risk"]["factors"]) - i["risk_score"]) < 0.1


def test_evaluation_summary_matches_the_api(client, auth_a, site_a, hero):
    from app.database import database
    from app.risk.evaluation import summarize
    from app.risk.scoring import run_risk_for_website
    with database.SessionLocal() as db:
        s = summarize(db, wid(site_a), run_risk_for_website(db, wid(site_a)))
    assert s["incidents"] == 1 and s["high_risk_incidents"] == 1 and s["events_with_findings"] > 0
    assert s["incidents_detail"][0]["risk_score"] == risk(client, auth_a, hero).json()["risk_score"] and "Not a real-world" in s["caveat"]
