"""API tests for the agent workflow (FR-16..FR-21, AC-10, AC-14..AC-19, AC-22). The LLM is always a scripted fake: no network, no CrewAI."""
import re

import pytest

from tests.agent_helpers import FakeRunner
from app.crew.crew import LLMCallError

# Refs that exist for every incident that has at least one finding: F1 (top finding) and C:correlation.
INV = {"hypothesis": {"statement": "The correlated activity is consistent with credential abuse.", "attack_category": "credential_abuse",
                      "model_confidence": 0.8, "refs": ["F1", "C:correlation"]},
       "supporting_evidence": [{"claim": "A top-confidence rule finding is part of this incident.", "refs": ["F1"]}],
       "missing_evidence": [{"description": "No independent evidence of account takeover.", "why_it_matters": "A successful login is not proof of takeover."}],
       "alternative_explanations": ["Automated testing by the site owner."]}
REC = {"recommendations": [{"action": "force_password_reset_review", "title": "Review targeted account", "rationale": "Login followed repeated failures.",
                            "priority": 1, "refs": ["F1"], "limitations": "Does not show post-login activity."}]}


def wid(site):
    return site["website"]["website_id"]


@pytest.fixture
def hero(client, auth_a, site_a):
    r = client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a)
    assert r.status_code == 200, r.text
    incs = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()
    assert len(incs) == 1
    return incs[0]["incident_id"]


@pytest.fixture
def use_runner(monkeypatch):
    def _use(runner):
        monkeypatch.setattr("app.api.investigation.get_runner", lambda: runner)
        return runner
    return _use


def test_config_endpoint_and_health(client):
    r = client.get("/v1/agents/config")
    assert r.status_code == 200 and r.json()["config"]["status"] == "ok" and r.json()["llm"]["configured"] is False
    assert "gsk_" not in r.text
    h = client.get("/health").json()
    assert h["agents_config"] == "ok" and h["version"].startswith("0.")


def test_all_routes_require_authentication(client, hero, site_a):
    for method, path in (("post", f"/v1/incidents/{hero}/investigate"), ("get", f"/v1/incidents/{hero}/investigation"),
                         ("get", f"/v1/incidents/{hero}/recommendations"), ("get", f"/v1/incidents/{hero}/alert"),
                         ("get", f"/v1/incidents/{hero}/audit"), ("post", f"/v1/websites/{wid(site_a)}/investigate"),
                         ("get", f"/v1/websites/{wid(site_a)}/alerts")):
        assert getattr(client, method)(path).status_code == 401, path


def test_full_workflow_with_fake_llm(client, auth_a, site_a, hero, use_runner):
    runner = use_runner(FakeRunner([INV, REC]))
    r = client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok" and runner.calls == 2
    assert body["inference"]["hypothesis"]["evidence_type"] == "ai_inference"     # the stored investigation is flattened into the response
    assert body["facts"] and body["stale"] is False
    assert body["prerequisites"].get("risk") == "ok"

    rec = client.get(f"/v1/incidents/{hero}/recommendations", headers=auth_a).json()
    assert rec["status"] == "ok" and rec["recommendations"]
    assert all(x["requires_human_approval"] is True and x["executed"] is False and x["status"] == "proposed" for x in rec["recommendations"])

    alert = client.get(f"/v1/incidents/{hero}/alert", headers=auth_a).json()
    assert alert["priority"] in ("P1", "P2") and alert["risk_level"] in ("HIGH", "CRITICAL") and alert["recommended_next_action"]["requires_human_approval"]

    audit = client.get(f"/v1/incidents/{hero}/audit", headers=auth_a).json()
    assert [a["action"] for a in audit["audit"]][:2] == ["ai_investigation_generated", "recommendations_proposed"]

    inc = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()[0]
    assert inc["status"] == "INVESTIGATING"                               # M10: an investigation run moves DETECTED -> INVESTIGATING
    tl = client.get(f"/v1/incidents/{hero}/timeline", headers=auth_a).json()["timeline"]
    ai = [e for e in tl if e["evidence_type"] == "ai_inference"]
    assert len(ai) == 1 and "not proof" in ai[0]["label"]
    alerts = client.get(f"/v1/websites/{wid(site_a)}/alerts", headers=auth_a).json()
    assert alerts["count"] == 1 and alerts["alerts"][0]["incident_id"] == hero


def test_llm_never_sees_ip_addresses(client, auth_a, hero, use_runner):
    runner = use_runner(FakeRunner([INV, REC]))
    assert client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()["status"] == "ok"
    for spec in runner.specs:
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", spec.description + spec.backstory)


def test_without_llm_the_deterministic_parts_still_work(client, auth_a, hero, use_runner):
    use_runner(FakeRunner([], configured=False))
    body = client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()
    assert body["status"] == "llm_unavailable" and body["error"]["code"] == "llm_unavailable"
    assert body["facts"] and body["inference"] is None
    assert client.get(f"/v1/incidents/{hero}/alert", headers=auth_a).json()["ai_status"] == "llm_unavailable"
    assert client.get(f"/v1/incidents/{hero}/risk", headers=auth_a).json()["risk_level"] in ("HIGH", "CRITICAL")


def test_default_runner_without_api_key_fails_safely(client, auth_a, hero):
    body = client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()     # real CrewAIRunner, GROQ_API_KEY is empty in tests
    assert body["status"] == "llm_unavailable" and "GROQ_API_KEY" in body["error"]["message"]


def test_failed_rerun_keeps_previous_successful_result(client, auth_a, hero, use_runner):
    use_runner(FakeRunner([INV, REC]))
    assert client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()["status"] == "ok"
    use_runner(FakeRunner([LLMCallError("rate_limit", "rate limited")]))
    again = client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()
    assert again["status"] == "llm_error" and again["error"]["kind"] == "rate_limit" and again["kept_previous_successful"] is True
    assert client.get(f"/v1/incidents/{hero}/investigation", headers=auth_a).json()["status"] == "ok"


def test_not_run_states(client, auth_a, hero):
    assert client.get(f"/v1/incidents/{hero}/investigation", headers=auth_a).json()["status"] == "not_run"
    assert client.get(f"/v1/incidents/{hero}/recommendations", headers=auth_a).json()["status"] == "not_run"
    assert client.get(f"/v1/incidents/{hero}/alert", headers=auth_a).json()["status"] == "no_alert"


def test_website_batch_investigation(client, auth_a, site_a, hero, use_runner):
    use_runner(FakeRunner([INV, REC]))
    body = client.post(f"/v1/websites/{wid(site_a)}/investigate", headers=auth_a).json()
    assert body["investigated"] == 1 and body["results"][0]["status"] == "ok" and body["cap"] <= 3


def test_other_customers_cannot_reach_investigation_data(client, auth_a, auth_b, site_a, hero, use_runner):
    use_runner(FakeRunner([INV, REC]))
    assert client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()["status"] == "ok"
    for method, path in (("post", f"/v1/incidents/{hero}/investigate"), ("get", f"/v1/incidents/{hero}/investigation"),
                         ("get", f"/v1/incidents/{hero}/recommendations"), ("get", f"/v1/incidents/{hero}/alert"),
                         ("get", f"/v1/incidents/{hero}/audit"), ("post", f"/v1/websites/{wid(site_a)}/investigate"),
                         ("get", f"/v1/websites/{wid(site_a)}/alerts")):
        assert getattr(client, method)(path, headers=auth_b).status_code == 404, path
