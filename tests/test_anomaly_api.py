"""Anomaly endpoints + persistence (M4). Needs the full stack (FastAPI/SQLAlchemy), unlike the pure model tests."""
import copy

from app.ml.config import AnomalyConfig, defaults


def wid(site):
    return site["website"]["website_id"]


def load_all_demo(client, auth, site):
    r = client.post(f"/v1/websites/{wid(site)}/demo/load", json={"scenario": "all", "analyze": True}, headers=auth)
    assert r.status_code == 200 and r.json()["synthetic"] is True
    return r.json()


def anomalies(client, auth, site, **params):
    r = client.get(f"/v1/websites/{wid(site)}/anomalies", params=params, headers=auth)
    assert r.status_code == 200
    return r.json()


def rule_finding_count(client, auth, site):
    fs = client.get(f"/v1/websites/{wid(site)}/findings", params={"limit": 500}, headers=auth).json()
    return len([f for f in fs if f["agent_name"] == "rule_engine"])


def test_endpoints_require_auth_and_isolate_accounts(client, auth_a, auth_b, site_a):
    w = wid(site_a)
    for method, path in [("post", f"/v1/websites/{w}/anomalies/analyze"), ("get", f"/v1/websites/{w}/anomalies")]:
        assert getattr(client, method)(path).status_code == 401
        assert getattr(client, method)(path, headers=auth_b).status_code == 404          # existence not disclosed


def test_config_endpoint_is_public_and_health_reports_it(client):
    body = client.get("/v1/anomaly/config").json()
    assert body["config"]["status"] == "ok" and body["config"]["score_threshold"] == 0.65
    assert body["model_available"] is True and len(body["features"]) == 10
    assert "not probabilities" in body["note"]
    assert "GROQ" not in str(body).upper()                                              # nothing secret-shaped
    assert client.get("/health").json()["anomaly_config"] == "ok"


def test_empty_website_reports_insufficient_baseline(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "insufficient_baseline" and body["flagged_sessions"] == 0 and body["findings_created"] == 0
    assert anomalies(client, auth_a, site_a) == []


def test_demo_data_flags_hero_and_bot_sessions_and_persists_findings(client, auth_a, site_a):
    load_all_demo(client, auth_a, site_a)
    rules_before = rule_finding_count(client, auth_a, site_a)
    body = client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a).json()
    assert body["status"] == "ok" and body["sessions_analyzed"] == 674
    flagged = {s["session_key"] for s in body["top_scored_sessions"] if s["flagged"]}
    assert flagged == {"sess-h-pre", "sess-bot-1"} and body["findings_created"] == 2 and body["findings_replaced"] == 0
    assert not any(s["session_key"].startswith(("sess-n", "sess-typo")) for s in body["top_scored_sessions"] if s["flagged"])

    fs = anomalies(client, auth_a, site_a)
    assert len(fs) == 2
    for f in fs:
        assert f["agent_name"] == "anomaly_model" and f["finding_type"] == "ml_anomaly" and f["rule_id"] == "M-ANOM-001"
        assert 0.5 <= f["confidence"] <= 0.9 and f["event_timestamp"]
        ev = f["evidence"]
        assert ev["interpretation"]["basis"] == "model_output_template" and ev["event_ids"] and ev["limitations"]
        assert ev["derived_metrics"]["anomaly_score"] >= 0.65 and ev["derived_metrics"]["notable_deviations"]
    hero = next(f for f in fs if f["evidence"]["observed"]["session_key"] == "sess-h-pre")
    assert hero["evidence"]["derived_metrics"]["notable_deviations"][0]["feature"] in ("login_failures", "requests_per_min")

    # ML findings coexist with rule findings and never alter them
    assert rule_finding_count(client, auth_a, site_a) == rules_before
    all_findings = client.get(f"/v1/websites/{wid(site_a)}/findings", params={"limit": 500}, headers=auth_a).json()
    assert {"rule_engine", "anomaly_model"} <= {f["agent_name"] for f in all_findings}
    assert anomalies(client, auth_a, site_a, min_confidence=0.99) == []


def test_reanalysis_is_idempotent(client, auth_a, site_a):
    load_all_demo(client, auth_a, site_a)
    first = client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a).json()
    second = client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a).json()
    assert first["findings_created"] == 2 and second["findings_created"] == 2 and second["findings_replaced"] == 2
    assert len(anomalies(client, auth_a, site_a)) == 2                                   # replaced, never duplicated


def test_other_accounts_never_see_these_findings(client, auth_a, auth_b, site_a):
    load_all_demo(client, auth_a, site_a)
    client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a)
    site_b = client.post("/v1/websites", json={"domain": "other.example.com"}, headers=auth_b).json()
    assert anomalies(client, auth_b, site_b) == []
    assert client.post(f"/v1/websites/{wid(site_b)}/anomalies/analyze", headers=auth_b).json()["status"] == "insufficient_baseline"
    assert len(anomalies(client, auth_a, site_a)) == 2                                   # B's run did not touch A's data


def test_disabled_model_changes_nothing(client, auth_a, site_a, monkeypatch):
    load_all_demo(client, auth_a, site_a)
    client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a)
    data = copy.deepcopy(defaults().data)
    data["enabled"] = False
    monkeypatch.setattr("app.ml.engine.get_anomaly_config", lambda: AnomalyConfig(data=data))
    r = client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a)
    assert r.status_code == 200 and r.json()["status"] == "disabled"
    assert len(anomalies(client, auth_a, site_a)) == 2                                   # earlier findings left in place


def test_model_failure_is_reported_not_raised(client, auth_a, site_a, monkeypatch):
    load_all_demo(client, auth_a, site_a)
    from app.ml import anomaly_model

    def boom():
        raise anomaly_model.ModelUnavailable("scikit-learn is not installed")
    monkeypatch.setattr(anomaly_model, "_load_isolation_forest", boom)
    r = client.post(f"/v1/websites/{wid(site_a)}/anomalies/analyze", headers=auth_a)
    assert r.status_code == 200 and r.json()["status"] == "model_unavailable" and r.json()["findings_created"] == 0
    assert rule_finding_count(client, auth_a, site_a) > 0                                # deterministic detection unaffected
