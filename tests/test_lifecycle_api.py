"""API tests for lifecycle, analyst feedback and recommendation decisions (FR-22, FR-23, AC-19, AC-20, AC-22). The LLM is always a scripted fake."""
import pytest

from tests.agent_helpers import FakeRunner
from tests.test_investigation_api import INV, REC
from app.crew.crew import LLMCallError


def wid(site):
    return site["website"]["website_id"]


@pytest.fixture
def hero(client, auth_a, site_a):
    assert client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a).status_code == 200
    incs = client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()
    assert len(incs) == 1
    return incs[0]["incident_id"]


@pytest.fixture
def use_runner(monkeypatch):
    def _use(runner):
        monkeypatch.setattr("app.api.investigation.get_runner", lambda: runner)
        return runner
    return _use


@pytest.fixture
def investigated(client, auth_a, hero, use_runner):
    use_runner(FakeRunner([INV, REC]))
    assert client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()["status"] == "ok"
    return hero


def status_of(client, auth, iid):
    return client.get(f"/v1/incidents/{iid}/lifecycle", headers=auth).json()


def fb(client, auth, iid, decision, comment=None):
    return client.post(f"/v1/incidents/{iid}/feedback", json={"decision": decision, "comment": comment}, headers=auth)


def st(client, auth, iid, status, comment=None):
    return client.post(f"/v1/incidents/{iid}/status", json={"status": status, "comment": comment}, headers=auth)


def test_config_is_public_and_complete(client):
    r = client.get("/v1/lifecycle/config")
    assert r.status_code == 200 and "RESPONSE_RECOMMENDED" in r.json()["states"] and r.json()["analyst_decisions"] == ["CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"]


def test_all_new_routes_require_authentication(client, hero):
    for method, path in (("get", f"/v1/incidents/{hero}/lifecycle"), ("post", f"/v1/incidents/{hero}/status"), ("post", f"/v1/incidents/{hero}/feedback"),
                         ("get", f"/v1/incidents/{hero}/feedback"), ("post", f"/v1/incidents/{hero}/recommendations/x/decision"), ("get", f"/v1/incidents/{hero}/report")):
        assert getattr(client, method)(path).status_code == 401, path


def test_other_customers_cannot_read_or_change_lifecycle_data(client, auth_a, auth_b, investigated):
    iid = investigated
    for method, path, body in (("get", f"/v1/incidents/{iid}/lifecycle", None), ("post", f"/v1/incidents/{iid}/status", {"status": "RESOLVED"}),
                               ("post", f"/v1/incidents/{iid}/feedback", {"decision": "false_positive"}), ("get", f"/v1/incidents/{iid}/feedback", None),
                               ("post", f"/v1/incidents/{iid}/recommendations/force_password_reset_review/decision", {"decision": "accept"}),
                               ("get", f"/v1/incidents/{iid}/report", None)):
        r = getattr(client, method)(path, headers=auth_b, **({"json": body} if body else {}))
        assert r.status_code == 404, path
    assert status_of(client, auth_a, iid)["status"] == "INVESTIGATING" and status_of(client, auth_a, iid)["feedback_count"] == 0


def test_new_incident_is_detected_and_investigation_moves_it_to_investigating(client, auth_a, hero, use_runner):
    v = status_of(client, auth_a, hero)
    assert v["status"] == "DETECTED" and v["closed"] is False and "INVESTIGATING" in v["allowed_next"] and v["history"] == []
    use_runner(FakeRunner([], configured=False))                     # even a failed AI run is an investigation attempt (deterministic parts ran)
    assert client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a).json()["status"] == "llm_unavailable"
    v = status_of(client, auth_a, hero)
    assert v["status"] == "INVESTIGATING" and v["history"][0]["actor"] == "system" and v["history"][0]["reason"] == "investigation_run"


def test_rerunning_the_investigation_never_resets_a_later_status(client, auth_a, investigated, use_runner):
    assert fb(client, auth_a, investigated, "needs_investigation").status_code == 201
    use_runner(FakeRunner([LLMCallError("rate_limit", "rate limited")]))
    client.post(f"/v1/incidents/{investigated}/investigate", headers=auth_a)
    assert status_of(client, auth_a, investigated)["status"] == "NEEDS_INVESTIGATION"


def test_feedback_is_stored_against_the_incident_and_moves_the_lifecycle(client, auth_a, hero):
    r = fb(client, auth_a, hero, "False Positive", "Load test from our own QA team.")
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["decision"] == "FALSE_POSITIVE" and b["status"] == "FALSE_POSITIVE" and b["closed"] is True and b["feedback_id"].startswith("fb_")
    rows = client.get(f"/v1/incidents/{hero}/feedback", headers=auth_a).json()
    assert rows["count"] == 1 and rows["feedback"][0]["analyst_decision"] == "FALSE_POSITIVE" and rows["feedback"][0]["comment"] == "Load test from our own QA team."
    inc = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    assert inc["status"] == "FALSE_POSITIVE" and inc["updated_at"] >= inc["created_at"]


def test_confirmed_without_recommendations_stays_confirmed(client, auth_a, hero):
    b = fb(client, auth_a, hero, "true_positive").json()
    assert b["status"] == "CONFIRMED" and b["auto_advanced_to_response_recommended"] is False


def test_confirmed_with_recommendations_advances_to_response_recommended_with_two_audited_steps(client, auth_a, investigated):
    b = fb(client, auth_a, investigated, "confirmed", "Matches our fraud team's report.").json()
    assert b["status"] == "RESPONSE_RECOMMENDED" and b["auto_advanced_to_response_recommended"] is True
    hist = b["history"]
    assert [(h["from"], h["to"], h["actor"].split(":")[0]) for h in hist] == [("DETECTED", "INVESTIGATING", "system"), ("INVESTIGATING", "CONFIRMED", "analyst"),
                                                                              ("CONFIRMED", "RESPONSE_RECOMMENDED", "system")]
    audit = client.get(f"/v1/incidents/{investigated}/audit", headers=auth_a).json()["audit"]
    assert [a["action"] for a in audit if a["actor"].startswith("analyst")] == ["status_changed", "analyst_decision"]
    assert all(a.get("executed") is not True for a in audit)


def test_alert_status_follows_the_lifecycle(client, auth_a, site_a, investigated):
    def alert_status():
        return client.get(f"/v1/websites/{wid(site_a)}/alerts", headers=auth_a).json()["alerts"][0]["status"]
    assert alert_status() == "open"
    fb(client, auth_a, investigated, "confirmed")                                   # -> CONFIRMED -> RESPONSE_RECOMMENDED
    assert alert_status() == "acknowledged"
    assert st(client, auth_a, investigated, "RESOLVED").status_code == 200 and alert_status() == "closed"
    assert st(client, auth_a, investigated, "INVESTIGATING", "Reopened after new evidence.").status_code == 200 and alert_status() == "open"
    assert fb(client, auth_a, investigated, "false_positive").status_code == 201 and alert_status() == "closed"
    assert client.get(f"/v1/incidents/{investigated}/alert", headers=auth_a).json()["status"] == "closed"


def test_response_recommended_cannot_jump_straight_to_false_positive(client, auth_a, investigated):
    fb(client, auth_a, investigated, "confirmed")
    r = fb(client, auth_a, investigated, "false_positive")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "invalid_transition"
    assert fb(client, auth_a, investigated, "needs_investigation").status_code == 201          # "further investigate" is the allowed way back (PRD section 21)
    assert fb(client, auth_a, investigated, "false_positive").status_code == 201
    assert client.get(f"/v1/incidents/{investigated}/feedback", headers=auth_a).json()["count"] == 3          # the refused decision stored nothing


def test_invalid_transition_is_a_controlled_409_and_changes_nothing(client, auth_a, hero):
    before = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    for target in ("RESOLVED", "ACTION_TAKEN", "RESPONSE_RECOMMENDED"):
        r = st(client, auth_a, hero, target, "x")
        assert r.status_code == 409 and r.json()["detail"]["code"] == "invalid_transition" and "INVESTIGATING" in r.json()["detail"]["allowed"]
    after = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    assert after["status"] == "DETECTED" and after["details"].get("audit") == before["details"].get("audit") and after["details"].get("lifecycle") is None


def test_unknown_status_decision_and_oversized_comment_are_422(client, auth_a, hero):
    assert st(client, auth_a, hero, "DELETED").status_code == 422
    assert fb(client, auth_a, hero, "malicious").status_code == 422
    assert fb(client, auth_a, hero, "false_positive", "x" * 2500).status_code == 422          # service limit (2000)
    assert fb(client, auth_a, hero, "false_positive", "x" * 6000).status_code == 422          # request-model limit
    assert client.get(f"/v1/incidents/{hero}/feedback", headers=auth_a).json()["count"] == 0 and status_of(client, auth_a, hero)["status"] == "DETECTED"


def test_decision_states_set_through_status_are_stored_as_feedback_too(client, auth_a, hero):
    b = st(client, auth_a, hero, "needs_investigation", "Need the web logs.").json()
    assert b["status"] == "NEEDS_INVESTIGATION" and b["decision"] == "NEEDS_INVESTIGATION"
    assert client.get(f"/v1/incidents/{hero}/feedback", headers=auth_a).json()["count"] == 1


def test_repeating_a_decision_stores_new_feedback_without_a_transition(client, auth_a, hero):
    fb(client, auth_a, hero, "confirmed", "first")
    second = fb(client, auth_a, hero, "confirmed", "added detail")
    assert second.status_code == 201 and second.json()["status"] == "CONFIRMED"
    rows = client.get(f"/v1/incidents/{hero}/feedback", headers=auth_a).json()["feedback"]
    assert [r["comment"] for r in rows] == ["added detail", "first"]                      # newest first
    assert len([h for h in status_of(client, auth_a, hero)["history"] if h["to"] == "CONFIRMED"]) == 1


def test_analyst_can_revise_a_decision(client, auth_a, hero):
    fb(client, auth_a, hero, "confirmed")
    b = fb(client, auth_a, hero, "false_positive", "Customer confirmed it was them.").json()
    assert b["status"] == "FALSE_POSITIVE" and b["feedback_count"] == 2 and b["latest_feedback"]["analyst_decision"] == "FALSE_POSITIVE"


def test_comment_is_stored_as_plain_text_with_control_characters_removed(client, auth_a, hero):
    fb(client, auth_a, hero, "confirmed", "<b>bold</b>\x00\x1b[31m red\nsecond line")
    c = client.get(f"/v1/incidents/{hero}/feedback", headers=auth_a).json()["feedback"][0]["comment"]
    assert "\x00" not in c and "\x1b" not in c and c.startswith("<b>bold</b>") and "\n" in c


def test_action_taken_requires_a_comment_and_an_accepted_recommendation(client, auth_a, investigated):
    iid = investigated
    fb(client, auth_a, iid, "confirmed")
    assert status_of(client, auth_a, iid)["status"] == "RESPONSE_RECOMMENDED"
    r = st(client, auth_a, iid, "ACTION_TAKEN")
    assert r.status_code == 422 and r.json()["detail"]["code"] == "comment_required"
    r = st(client, auth_a, iid, "ACTION_TAKEN", "Reset the password of the targeted account.")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "approval_required" and r.json()["detail"]["recommendations"] == ["force_password_reset_review"]
    assert status_of(client, auth_a, iid)["status"] == "RESPONSE_RECOMMENDED"
    d = client.post(f"/v1/incidents/{iid}/recommendations/force_password_reset_review/decision", json={"decision": "accept", "comment": "Approved."}, headers=auth_a)
    assert d.status_code == 200 and d.json()["decision"] == "accepted" and d.json()["executed"] is False
    ok = st(client, auth_a, iid, "ACTION_TAKEN", "Reset the password of the targeted account.")
    assert ok.status_code == 200 and ok.json()["status"] == "ACTION_TAKEN"
    h = ok.json()["history"][-1]
    assert h["to"] == "ACTION_TAKEN" and h["comment"] == "Reset the password of the targeted account." and h["actor"].startswith("analyst:")
    assert st(client, auth_a, iid, "RESOLVED").json()["closed"] is True


def test_rejecting_all_recommendations_still_allows_resolving_without_action(client, auth_a, investigated):
    iid = investigated
    fb(client, auth_a, iid, "confirmed")
    client.post(f"/v1/incidents/{iid}/recommendations/force_password_reset_review/decision", json={"decision": "reject"}, headers=auth_a)
    assert st(client, auth_a, iid, "ACTION_TAKEN", "did something").status_code == 409
    assert st(client, auth_a, iid, "RESOLVED").status_code == 200


def test_recommendation_decision_is_visible_but_never_executes_anything(client, auth_a, investigated):
    iid = investigated
    client.post(f"/v1/incidents/{iid}/recommendations/force_password_reset_review/decision", json={"decision": "further_investigation", "comment": "Need logs"}, headers=auth_a)
    rec = client.get(f"/v1/incidents/{iid}/recommendations", headers=auth_a).json()["recommendations"][0]
    assert rec["analyst_decision"]["decision"] == "needs_investigation" and rec["analyst_decision"]["comment"] == "Need logs"
    assert rec["status"] == "proposed" and rec["executed"] is False and rec["requires_human_approval"] is True
    audit = [a for a in client.get(f"/v1/incidents/{iid}/audit", headers=auth_a).json()["audit"] if a["action"] == "recommendation_decision"]
    assert len(audit) == 1 and audit[0]["executed"] is False and audit[0]["actor"].startswith("analyst:")
    assert status_of(client, auth_a, iid)["status"] == "INVESTIGATING"                  # a recommendation decision alone does not move the incident


def test_recommendation_decision_errors(client, auth_a, hero, investigated):
    iid = investigated
    assert client.post(f"/v1/incidents/{iid}/recommendations/not_a_real_action/decision", json={"decision": "accept"}, headers=auth_a).status_code == 404
    assert client.post(f"/v1/incidents/{iid}/recommendations/force_password_reset_review/decision", json={"decision": "execute"}, headers=auth_a).status_code == 422


def test_recommendation_decision_without_any_recommendations_is_404(client, auth_a, hero):
    assert client.post(f"/v1/incidents/{hero}/recommendations/force_password_reset_review/decision", json={"decision": "accept"}, headers=auth_a).status_code == 404


def test_resolved_incidents_can_only_be_reopened(client, auth_a, hero):
    fb(client, auth_a, hero, "false_positive")
    assert st(client, auth_a, hero, "RESOLVED").status_code == 200
    assert st(client, auth_a, hero, "CONFIRMED").status_code == 409
    assert st(client, auth_a, hero, "INVESTIGATING").json()["status"] == "INVESTIGATING"


def test_lifecycle_data_survives_a_correlation_rerun_and_a_reinvestigation(client, auth_a, site_a, investigated, use_runner):
    iid = investigated
    fb(client, auth_a, iid, "confirmed", "keep me")
    client.post(f"/v1/incidents/{iid}/recommendations/force_password_reset_review/decision", json={"decision": "accept"}, headers=auth_a)
    assert client.post(f"/v1/websites/{wid(site_a)}/correlate", headers=auth_a).status_code == 200
    use_runner(FakeRunner([INV, REC]))
    client.post(f"/v1/incidents/{iid}/investigate", headers=auth_a)
    v = status_of(client, auth_a, iid)
    assert v["status"] == "RESPONSE_RECOMMENDED" and v["feedback_count"] == 1 and v["recommendation_decisions"]["force_password_reset_review"]["decision"] == "accepted"
    assert [i["incident_id"] for i in client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()] == [iid]
