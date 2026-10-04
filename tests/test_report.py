"""Tests for the structured incident report (PRD section 24, FR-24, AC-21): builder (pure), renderers (escaping) and API."""
import copy
import re
from datetime import datetime, timezone

import pytest

from app.report.builder import build_report
from app.report.render import md_text, to_html, to_markdown
from tests.agent_helpers import FakeRunner, make_incident
from tests.test_investigation_api import INV, REC

PRD_SECTION_24_KEYS = ["incident_id", "detection_time", "affected_resources", "source_information", "attack_hypothesis", "timeline", "attack_graph_summary",
                       "supporting_evidence", "threat_intelligence", "risk", "mitre_attack", "recommended_response", "evidence_limitations", "analyst_decision"]
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
EVIL = "<script>alert(1)</script> | **bold** [x](javascript:alert(1)) ![i](http://e/x.png)"


def _inc(**details_over):
    inc = make_incident()
    inc.update(website_id="web_t", status="INVESTIGATING", risk_level="HIGH", risk_score=81.9, confidence=0.6, created_at=NOW)
    inc["details"].update(details_over)
    return inc


def _timeline():
    return [{"timestamp": "2026-10-03T10:31:02+00:00", "evidence_type": "observed", "label": "126 failed login attempts", "event_count": 126, "event_ids": [f"e{i}" for i in range(40)], "entry_id": "tl_001"},
            {"timestamp": "2026-10-03T10:31:50+00:00", "evidence_type": "system", "label": "Incident correlated", "event_count": 0, "event_ids": [], "entry_id": "tl_002"}]


def _graph():
    return {"nodes": [{"id": "n1", "type": "source", "label": "SOURCE IP", "layer": 0}, {"id": "n2", "type": "stage", "label": "Login attempts", "layer": 1}],
            "edges": [{"id": "e1", "relationship_type": "same_ip"}], "node_count": 2, "edge_count": 1}


def _inv(status="ok"):
    return {"status": status, "model": "fake", "generated_at": NOW.isoformat(), "error": None, "context_notes": ["1 finding was not sent to the model"],
            "facts": [{"evidence_type": "observed", "text": "126 failed logins in 18 s.", "refs": ["S:credential_attack"]}],
            "inference": {"hypothesis": {"statement": "Consistent with credential abuse.", "attack_category": "credential_abuse", "confidence": 0.6, "confidence_basis": "capped; not a probability",
                                         "refs": ["F1"], "event_ids": ["e1"]},
                          "supporting_evidence": [{"claim": "A burst rule fired.", "refs": ["F1"], "event_ids": ["e1"]}],
                          "missing_evidence": [{"description": "No independent evidence of takeover.", "why_it_matters": "Login success is not takeover."}],
                          "alternative_explanations": ["Site-owner testing."]} if status == "ok" else None}


def _report(**kw):
    base = dict(incident=_inc(), timeline=_timeline(), graph=_graph(), feedback=[], investigation=_inv(), now=NOW)
    base.update(kw)
    return build_report(**base)


def test_report_contains_every_prd_section_24_item():
    r = _report()
    for k in PRD_SECTION_24_KEYS:
        assert k in r, k
    assert r["incident_id"] == "inc_test1" and r["affected_resources"] == ["/api/admin/export"]
    assert r["detection_time"]["first_seen"] and r["source_information"]["source_ip_count"] == 1 and r["source_information"]["session_count"] == 2


def test_ai_text_is_labelled_inference_and_facts_are_kept_separate():
    r = _report()
    h = r["attack_hypothesis"]
    assert h["available"] and h["evidence_type"] == "ai_inference" and h["ai_generated"] is True and "not proof" in h["note"] and h["refs"] == ["F1"]
    assert all(f["evidence_type"] == "observed" for f in r["supporting_evidence"]["facts"])
    assert all(c["evidence_type"] == "ai_inference" for c in r["supporting_evidence"]["ai_supporting_claims"])
    assert r["evidence_limitations"]["ai_missing_evidence"][0]["evidence_type"] == "missing_evidence"
    assert r["evidence_limitations"]["deterministic_evidence_gaps"] and r["evidence_limitations"]["context_notes"]


def test_without_a_validated_ai_investigation_no_hypothesis_is_invented():
    for inv in (None, {"status": "not_run"}, _inv("llm_unavailable")):
        r = _report(investigation=inv)
        assert r["attack_hypothesis"]["available"] is False and "statement" not in r["attack_hypothesis"]
        assert "No validated AI hypothesis" in r["executive_summary"]


def test_risk_and_confidence_are_separate_and_factors_are_listed():
    r = _report()["risk"]
    assert r["risk_level"] == "HIGH" and r["risk_score"] == 81.9 and r["confidence"] == 0.6 and "Neither is a probability" in r["note"]
    assert {f["factor"] for f in r["factors"]} == {"authentication", "threat_intel"} and all("points" in f for f in r["factors"])


def test_threat_intelligence_no_evidence_rule_in_the_report():
    r = _report()
    assert r["threat_intelligence"]["status"] == "not_run" and "No threat-intelligence evidence was found" in r["threat_intelligence"]["notes"][0]
    ti = {"status": "ok", "retrieved_at": NOW.isoformat(), "indicators_checked": 1, "counts": {"no_evidence": 1}, "contains_synthetic": False, "notes": [], "disclaimers": [],
          "results": [{"indicator_type": "ip", "indicator": "203.0.113.77", "provider": "otx", "status": "no_evidence", "evidence_status": "no_evidence",
                       "summary": "No threat-intelligence evidence was found.", "synthetic": False}]}
    r = _report(incident=_inc(threat_intel=ti))
    assert any("not a claim of safety or of maliciousness" in n for n in r["threat_intelligence"]["notes"])
    assert r["mitre_attack"]["techniques"] == [] and "No MITRE" in r["mitre_attack"]["note"]


def test_mitre_techniques_come_only_from_found_enrichment_results():
    ti = {"status": "ok", "indicators_checked": 2, "results": [
        {"indicator_type": "attack_technique", "indicator": "T1110", "provider": "mitre_attack", "status": "evidence_found", "evidence_status": "evidence_found", "summary": "x",
         "data": {"technique_id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "url": "https://attack.mitre.org/techniques/T1110/"}},
        {"indicator_type": "attack_technique", "indicator": "T9999", "provider": "mitre_attack", "status": "no_evidence", "evidence_status": "no_evidence", "summary": "none", "data": {}}]}
    m = _report(incident=_inc(threat_intel=ti))["mitre_attack"]
    assert [t["technique_id"] for t in m["techniques"]] == ["T1110"] and "not proof" in m["note"]


def test_recommendations_are_proposals_with_the_analyst_decision_attached():
    rec = {"status": "ok", "model": "fake", "recommendations": [{"action": "block_source_review", "title": "Review source", "rationale": "r", "priority": 1, "refs": ["F1"],
                                                                 "requires_human_approval": False, "executed": True, "status": "proposed"}]}      # even a tampered record cannot claim execution
    r = _report(incident=_inc(recommendations=rec, recommendation_decisions={"block_source_review": {"decision": "accepted", "comment": "ok", "decided_at": "t"}}))
    x = r["recommended_response"]["recommendations"][0]
    assert x["requires_human_approval"] is True and x["executed"] is False and x["analyst_decision"]["decision"] == "accepted"
    assert _report()["recommended_response"]["recommendations"] == [] and "analyst decides" in _report()["recommended_response"]["note"]


def test_analyst_decision_section():
    r = _report(feedback=[{"feedback_id": "fb_2", "analyst_decision": "CONFIRMED", "comment": "Matches fraud report", "created_at": NOW},
                          {"feedback_id": "fb_1", "analyst_decision": "NEEDS_INVESTIGATION", "comment": None, "created_at": NOW}])
    a = r["analyst_decision"]
    assert a["decision"] == "CONFIRMED" and a["comment"] == "Matches fraud report" and len(a["feedback_history"]) == 2 and "Analyst decision: CONFIRMED" in r["executive_summary"]
    assert _report()["analyst_decision"]["decision"] is None and "No analyst decision" in _report()["analyst_decision"]["note"]


def test_timeline_and_graph_summary_are_traceable():
    r = _report()
    assert [e["timestamp"] for e in r["timeline"]["entries"]] == sorted(e["timestamp"] for e in r["timeline"]["entries"])
    assert len(r["timeline"]["entries"][0]["event_ids"]) <= 10 and r["timeline"]["entry_count"] == 2
    g = r["attack_graph_summary"]
    assert g["node_count"] == 2 and g["edge_count"] == 1 and g["layered_path"] == ["SOURCE IP", "Login attempts"] and "event ids" in g["traceability"]


def test_builder_is_deterministic_and_does_not_mutate_its_inputs():
    inc, tl = _inc(), _timeline()
    before = copy.deepcopy((inc, tl))
    a, b = _report(incident=inc, timeline=tl), _report(incident=inc, timeline=tl)
    assert a == b and (inc, tl) == before and a["generated_by"].endswith("(no LLM)")


def test_synthetic_data_is_flagged():
    assert _report()["contains_synthetic_data"] is True
    assert "SYNTHETIC DEMO DATA" in to_markdown(_report())


# --------------------------------------------------------------------------------------------------------- escaping
def test_markdown_renderer_neutralises_untrusted_text():
    inc = _inc(affected_resources=[EVIL])
    md = to_markdown(_report(incident=inc, feedback=[{"feedback_id": "f", "analyst_decision": "CONFIRMED", "comment": EVIL, "created_at": NOW}]))
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert not re.search(r"(?<!\\)\[x\]\(", md) and not re.search(r"(?<!\\)!\[", md)            # links / images are escaped
    for line in md.splitlines():
        if line.startswith("| ") and "bold" in line:
            assert "\\|" in line                                                                  # the pipe cannot break out of its table cell
    assert md_text("a\x00b\nc") == "a b c" and md_text("inc_ab12") == "inc_ab12" and md_text("_em_ and __x__") == "\\_em\\_ and \\_\\_x\\_\\_"


def test_html_renderer_escapes_everything_dynamic_and_has_no_active_content():
    inc = _inc(affected_resources=[EVIL])
    out = to_html(_report(incident=inc, feedback=[{"feedback_id": "f", "analyst_decision": "CONFIRMED", "comment": EVIL, "created_at": NOW}]))
    assert "<script" not in out.lower().replace("&lt;script", "") and "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "Content-Security-Policy" in out and "default-src &#x27;none&#x27;" in out
    assert not re.search(r"<(script|iframe|img|link|object|embed|form)\b", out, re.I) and 'href="' not in out


def test_markdown_and_html_cover_the_prd_sections():
    md, html_out = to_markdown(_report()), to_html(_report())
    for heading in ("Timeline", "Attack graph summary", "Supporting evidence", "Threat intelligence", "MITRE ATT&CK", "Risk and confidence", "Recommended response",
                    "Evidence limitations", "Analyst decision", "Attack hypothesis"):
        assert heading.replace("&", "&amp;") in md, heading                     # "&" is entity-escaped in both renderers
        assert heading.replace("&", "&amp;") in html_out, heading


# --------------------------------------------------------------------------------------------------------- API
def wid(site):
    return site["website"]["website_id"]


@pytest.fixture
def hero(client, auth_a, site_a):
    assert client.post(f"/v1/websites/{wid(site_a)}/demo/load", json={"scenario": "hero_credential_abuse"}, headers=auth_a).status_code == 200
    return client.get(f"/v1/websites/{wid(site_a)}/incidents", headers=auth_a).json()[0]["incident_id"]


@pytest.fixture
def use_runner(monkeypatch):
    def _use(runner):
        monkeypatch.setattr("app.api.investigation.get_runner", lambda: runner)
        return runner
    return _use


def test_report_api_json_for_an_uninvestigated_incident(client, auth_a, hero):
    r = client.get(f"/v1/incidents/{hero}/report", headers=auth_a)
    assert r.status_code == 200
    b = r.json()
    for k in PRD_SECTION_24_KEYS:
        assert k in b, k
    assert b["incident_id"] == hero and b["attack_hypothesis"]["available"] is False and b["timeline"]["entry_count"] > 0 and b["risk"]["risk_level"] in ("HIGH", "CRITICAL")
    assert b["analyst_decision"]["decision"] is None and b["contains_synthetic_data"] is True


def test_report_api_full_flow_matches_timeline_and_graph_endpoints(client, auth_a, hero, use_runner):
    use_runner(FakeRunner([INV, REC]))
    client.post(f"/v1/incidents/{hero}/investigate", headers=auth_a)
    client.post(f"/v1/incidents/{hero}/feedback", json={"decision": "confirmed", "comment": "Verified with the account owner."}, headers=auth_a)
    client.post(f"/v1/incidents/{hero}/recommendations/force_password_reset_review/decision", json={"decision": "accept"}, headers=auth_a)
    b = client.get(f"/v1/incidents/{hero}/report", headers=auth_a).json()
    tl = client.get(f"/v1/incidents/{hero}/timeline", headers=auth_a).json()
    g = client.get(f"/v1/incidents/{hero}/graph", headers=auth_a).json()
    assert b["timeline"]["entry_count"] == tl["entry_count"] and b["attack_graph_summary"]["node_count"] == g["node_count"] and b["attack_graph_summary"]["edge_count"] == g["edge_count"]
    assert b["attack_hypothesis"]["available"] and b["attack_hypothesis"]["evidence_type"] == "ai_inference" and b["attack_hypothesis"]["stale"] is False
    assert b["analyst_decision"]["decision"] == "CONFIRMED" and b["analyst_decision"]["comment"] == "Verified with the account owner." and b["status"] == "RESPONSE_RECOMMENDED"
    rec = b["recommended_response"]["recommendations"][0]
    assert rec["analyst_decision"]["decision"] == "accepted" and rec["executed"] is False and rec["requires_human_approval"] is True
    assert any(e["action"] == "analyst_decision" for e in b["audit_trail"]["entries"]) and b["alert"]["status"] == "acknowledged"
    assert len(b["analyst_decision"]["status_history"]) == 3


def test_report_generation_writes_nothing(client, auth_a, hero):
    before = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    for fmt in ("json", "markdown", "html"):
        assert client.get(f"/v1/incidents/{hero}/report?format={fmt}", headers=auth_a).status_code == 200
    after = client.get(f"/v1/incidents/{hero}", headers=auth_a).json()
    assert before["updated_at"] == after["updated_at"] and before["details"] == after["details"] and before["status"] == after["status"]


def test_report_api_markdown_and_html_formats_and_headers(client, auth_a, hero):
    md = client.get(f"/v1/incidents/{hero}/report?format=markdown&download=true", headers=auth_a)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown") and md.text.startswith(f"# Incident report {hero}")
    assert md.headers["content-disposition"] == f'attachment; filename="{hero}-report.md"' and md.headers["x-content-type-options"] == "nosniff"
    h = client.get(f"/v1/incidents/{hero}/report?format=html", headers=auth_a)
    assert h.status_code == 200 and h.headers["content-type"].startswith("text/html") and "content-disposition" not in h.headers
    assert "default-src 'none'" in h.headers["content-security-policy"] and "<script" not in h.text.lower()


def test_report_api_rejects_unknown_format(client, auth_a, hero):
    assert client.get(f"/v1/incidents/{hero}/report?format=pdf", headers=auth_a).status_code == 422


def test_report_api_escapes_a_hostile_analyst_comment(client, auth_a, hero):
    client.post(f"/v1/incidents/{hero}/feedback", json={"decision": "false_positive", "comment": EVIL}, headers=auth_a)
    assert "<script>" not in client.get(f"/v1/incidents/{hero}/report?format=html", headers=auth_a).text
    assert "<script>" not in client.get(f"/v1/incidents/{hero}/report?format=markdown", headers=auth_a).text
    assert client.get(f"/v1/incidents/{hero}/report", headers=auth_a).json()["analyst_decision"]["comment"] == EVIL        # JSON keeps the raw text; renderers escape it
