"""API tests for threat-intelligence enrichment (FR-13, AC-11, AC-12, AC-22)."""
from dataclasses import replace

import httpx
import pytest

from app.config import get_settings
from app.threat_intel import providers as P
from app.threat_intel import service as S
from app.threat_intel.config import defaults
from tests.ti_helpers import mock_client, otx_body


def wid(site):
    return site["website"]["website_id"]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """No test may touch the real network: make_client fails unless a test installs a mock."""
    P.nvd_limiter.reset()
    S.clear_cache()

    def no_net():
        raise AssertionError("real HTTP client requested in a test")
    monkeypatch.setattr(S, "make_client", no_net)
    yield
    S.clear_cache()


def use_settings(monkeypatch, **over):
    s = replace(get_settings(), **over)
    monkeypatch.setattr(S, "get_settings", lambda: s)
    import app.api.threat_intel as api
    monkeypatch.setattr(api, "get_settings", lambda: s)
    return s


def use_mock(monkeypatch, handler):
    monkeypatch.setattr(S, "make_client", lambda: mock_client(handler))


@pytest.fixture
def hero(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a)
    assert r.status_code == 200, r.text
    incs = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()
    assert len(incs) == 1
    return incs[0]["incident_id"]


def post(client, auth, iid):
    return client.post(f"/v1/incidents/{iid}/threat-intel", headers=auth)


def by_type(rep):
    out = {}
    for r in rep["results"]:
        out.setdefault(r["indicator_type"], []).append(r)
    return out


def test_providers_endpoint_is_public_and_never_leaks_secrets(client, monkeypatch):
    use_settings(monkeypatch, ti_provider="otx", ti_api_key="otx-top-secret", nvd_api_key="nvd-top-secret")
    r = client.get("/v1/threat-intel/providers")
    assert r.status_code == 200 and r.json()["providers"]["reputation"]["status"] == "ok"
    assert "otx-top-secret" not in r.text and "nvd-top-secret" not in r.text
    assert r.json()["providers"]["cve"]["api_key_set"] is True


def test_health_reports_threat_intel_state_without_secrets(client, monkeypatch):
    import app.main as m
    s = replace(get_settings(), ti_provider="otx", ti_api_key="otx-top-secret")
    monkeypatch.setattr(m, "get_settings", lambda: s)
    h = client.get("/health").json()
    assert h["threat_intel_configured"] is True and h["threat_intel_provider"] == "otx" and h["threat_intel_config"] == "ok"
    assert "otx-top-secret" not in str(h) and h["version"].startswith("0.")


def test_get_before_any_run_says_not_run(client, auth_a, hero):
    rep = client.get(f"/v1/incidents/{hero}/threat-intel", headers=auth_a).json()
    assert rep["status"] == "not_run" and rep["results"] == []


def test_auth_and_isolation(client, auth_a, auth_b, site_a, hero):
    assert client.post(f"/v1/incidents/{hero}/threat-intel").status_code == 401
    assert client.get(f"/v1/incidents/{hero}/threat-intel").status_code == 401
    for call in (client.get, client.post):
        assert call(f"/v1/incidents/{hero}/threat-intel", headers=auth_b).status_code == 404
    assert client.post(f"/v1/websites/{wid(site_a)}/threat-intel/enrich", headers=auth_b).status_code == 404
    assert client.post("/v1/incidents/inc_missing/threat-intel", headers=auth_a).status_code == 404


def test_hero_without_a_reputation_provider_is_explicit_and_still_gives_attack_context(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="", ti_api_key="")
    rep = post(client, auth_a, hero).json()
    t = by_type(rep)
    assert rep["status"] == "ok" and rep["contains_synthetic"] is False
    assert [r["status"] for r in t["ip"]] == ["not_configured"] and "No threat-intelligence evidence is available" in t["ip"][0]["summary"]
    assert {r["indicator"] for r in t["attack_technique"]} == {"T1110", "T1078", "T1190"}
    assert all(r["status"] == "evidence_found" and r["source"] for r in t["attack_technique"])
    assert "cve" not in t                                            # no CVE signal in the hero chain: nothing invented
    assert any("not proof" in d for d in rep["disclaimers"])


def test_hero_with_real_provider_never_sends_documentation_ip(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="otx", ti_api_key="otx-key")
    use_mock(monkeypatch, lambda req: pytest.fail(f"unexpected outbound request to {req.url}"))
    rep = post(client, auth_a, hero).json()
    ip = by_type(rep)["ip"][0]
    assert ip["status"] == "not_applicable" and ip["provider"] == "otx" and "not sent to an external provider" in ip["summary"]


def test_hero_with_otx_when_non_public_queries_allowed(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="otx", ti_api_key="otx-key")
    cfg = defaults()
    cfg.data["indicators"]["ips"]["query_non_public"] = True
    monkeypatch.setattr(S, "get_ti_config", lambda: cfg)
    seen = []

    def h(req):
        seen.append((str(req.url), req.headers.get("X-OTX-API-KEY")))
        return httpx.Response(200, json=otx_body(4, country_name="Nowhere"))

    use_mock(monkeypatch, h)
    rep = post(client, auth_a, hero).json()
    assert seen == [("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.77/general", "otx-key")]
    ip = by_type(rep)["ip"][0]
    assert ip["status"] == "evidence_found" and ip["data"]["pulse_count"] == 4 and ip["synthetic"] is False
    assert "otx-key" not in str(rep)


def test_provider_outage_is_partial_and_investigation_continues(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="otx", ti_api_key="otx-key")
    cfg = defaults()
    cfg.data["indicators"]["ips"]["query_non_public"] = True
    monkeypatch.setattr(S, "get_ti_config", lambda: cfg)
    use_mock(monkeypatch, lambda req: httpx.Response(503))
    r = post(client, auth_a, hero)
    rep = r.json()
    assert r.status_code == 200 and rep["status"] == "partial" and rep["counts"]["error"] == 1
    assert by_type(rep)["ip"][0]["status"] == "error" and by_type(rep)["attack_technique"][0]["status"] == "evidence_found"
    assert client.get(f"/v1/incidents/{hero}", headers=auth_a).status_code == 200      # the incident itself is unaffected


def test_synthetic_demo_provider_is_flagged_everywhere_and_adds_timeline_step(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="synthetic_demo")
    rep = post(client, auth_a, hero).json()
    ip = by_type(rep)["ip"][0]
    assert ip["status"] == "evidence_found" and ip["synthetic"] is True and ip["summary"].startswith("SYNTHETIC DEMO DATA")
    assert rep["contains_synthetic"] is True and any("SYNTHETIC" in n for n in rep["notes"])
    tl = client.get(f"/v1/incidents/{hero}/timeline", headers=auth_a).json()["timeline"]
    last = tl[-1]
    assert last["evidence_type"] == "system" and last["label"].startswith("Threat intelligence enrichment: 4 indicators checked") and "SYNTHETIC" in last["label"]
    assert tl[-2]["label"] == "Incident correlated"


def test_timeline_has_no_enrichment_step_before_a_run(client, auth_a, hero):
    labels = [e["label"] for e in client.get(f"/v1/incidents/{hero}/timeline", headers=auth_a).json()["timeline"]]
    assert not any(l.startswith("Threat intelligence") for l in labels)


def test_enrichment_is_idempotent_and_does_not_touch_risk_or_status(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="synthetic_demo")
    before = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()      # the demo loader scored it (M7)
    a = post(client, auth_a, hero).json()
    b = post(client, auth_a, hero).json()
    assert [r["indicator"] for r in a["results"]] == [r["indicator"] for r in b["results"]] and a["counts"] == b["counts"]
    inc = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    # enrichment must leave the stored risk columns and the lifecycle status exactly as they were
    assert (inc["risk_level"], inc["risk_score"], inc["confidence"], inc["status"]) == (before["risk_level"], before["risk_score"], before["confidence"], "DETECTED")
    assert client.get(f"/v1/incidents/{hero}/threat-intel", headers=auth_a).json()["counts"] == b["counts"]


def test_correlation_rerun_preserves_the_threat_intel_report(client, auth_a, site_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="synthetic_demo")
    before = post(client, auth_a, hero).json()
    assert client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).status_code == 200
    after = client.get(f"/v1/incidents/{hero}/threat-intel", headers=auth_a).json()
    assert after["status"] == "ok" and after["retrieved_at"] == before["retrieved_at"] and after["counts"] == before["counts"]


def test_disabled_config_writes_nothing(client, auth_a, hero, monkeypatch):
    cfg = defaults()
    cfg.data["enabled"] = False
    monkeypatch.setattr(S, "get_ti_config", lambda: cfg)
    assert post(client, auth_a, hero).json()["status"] == "disabled"
    assert client.get(f"/v1/incidents/{hero}/threat-intel", headers=auth_a).json()["status"] == "not_run"


def test_enrichment_failure_is_contained(client, auth_a, hero, monkeypatch):
    use_settings(monkeypatch, ti_provider="")
    monkeypatch.setattr(S, "extract_indicators", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = post(client, auth_a, hero)
    assert r.status_code == 200 and r.json()["status"] == "error" and "boom" not in r.text
    assert client.get(f"/v1/incidents/{hero}/threat-intel", headers=auth_a).json()["status"] == "not_run"


def test_website_enrich_covers_every_demo_incident(client, auth_a, site_a, monkeypatch):
    use_settings(monkeypatch, ti_provider="synthetic_demo")
    client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "all"}, headers=auth_a)
    out = client.post(f"/v1/websites/{wid(site_a)}/threat-intel/enrich", headers=auth_a).json()
    assert out["incidents"] == 3 and {r["status"] for r in out["reports"]} == {"ok"} and all(r["contains_synthetic"] for r in out["reports"])
