"""M9 dashboard logic tests (PRD 23, AC-12..AC-16). Plain-assert functions (no pytest import), no Streamlit, no network, no DB.
Fixtures reuse real M8 output shapes (agent_helpers + investigate_core) so the view-models are checked against actual backend data."""
import sys

from app.agents.config import defaults
from app.crew.orchestration import investigate_core
from dashboard import viewmodels as vm
from tests.agent_helpers import GOOD_INVESTIGATION, GOOD_RESPONSE, FakeRunner, make_findings, make_incident, make_timeline


def _outcome(level="HIGH"):
    return investigate_core(incident=make_incident(level), findings=make_findings(), timeline=make_timeline(),
                            runner=FakeRunner([GOOD_INVESTIGATION, GOOD_RESPONSE]), cfg=defaults())


def test_md_escape_neutralises_markdown_html_and_control_chars():
    out = vm.md_escape("<script>alert(1)</script> [x](http://evil) `rm -rf` \x00\x1b *b*")
    assert "<" not in out.replace("\\<", "") and ">" not in out.replace("\\>", "")
    assert "\\[x\\]\\(http://evil\\)" in out and "\x00" not in out and "\x1b" not in out
    assert vm.md_escape(None) == ""
    assert len(vm.md_escape("a" * 1000, max_len=50)) <= 50


def test_evidence_labels_keep_prd19_separation():
    assert vm.evidence_label("observed") == "Observed fact"
    assert "not proof" in vm.evidence_label("ai_inference") and "not proof" in vm.evidence_label("derived_indicator")
    assert vm.evidence_label("missing_evidence") == "Missing evidence"
    assert "human approval" in vm.evidence_label("recommendation")
    assert vm.evidence_label("something_new") == "Unlabelled" and vm.evidence_label(None) == "Unlabelled"
    assert len({vm.evidence_label(t) for t in ("observed", "derived_metric", "ai_inference", "missing_evidence")}) == 4


def test_suspicious_event_count_is_distinct_and_includes_cited_events():
    fs = [{"event_id": "e1", "evidence": {"event_ids": ["e1", "e2", "e3"]}}, {"event_id": "e3", "evidence": {}}, {"event_id": "e9"}]
    assert vm.suspicious_event_count(fs) == 4
    assert vm.suspicious_event_count([]) == 0


def test_dashboard_kpis_exclude_closed_incidents_and_flag_lower_bound():
    inc = [{"risk_level": "HIGH", "status": "DETECTED"}, {"risk_level": "CRITICAL", "status": "RESOLVED"},
           {"risk_level": "LOW", "status": "INVESTIGATING"}, {"risk_level": None, "status": "FALSE_POSITIVE"}]
    k = vm.dashboard_kpis({"status": "active", "events_received": 9518}, [{"event_id": "e1"}], inc, [{"status": "open"}, {"status": "acknowledged"}], findings_limit=1)
    assert k["total_events"] == 9518 and k["active_incidents"] == 2 and k["high_risk_incidents"] == 1
    assert k["open_alerts"] == 1 and k["suspicious_events_is_lower_bound"] is True and k["monitoring_status"] == "active"
    k0 = vm.dashboard_kpis(None, None, None, None)
    assert k0["total_events"] == 0 and k0["active_incidents"] == 0 and k0["monitoring_status"] == "unknown"


def test_funnel_uses_measured_values_only():
    rows = vm.funnel_rows(vm.dashboard_kpis({"status": "active", "events_received": 9518}, [{"event_id": "e1"}], [{"risk_level": "HIGH"}], []))
    assert [r["count"] for r in rows] == [9518, 1, 1, 1]
    assert 10000 not in [r["count"] for r in rows] and 47 not in [r["count"] for r in rows]


def test_incident_cards_sort_by_risk_with_unscored_last_and_carry_alert():
    incs = [{"incident_id": "a", "title": "low", "risk_level": "LOW", "risk_score": 20.0},
            {"incident_id": "b", "title": "unscored", "risk_level": None, "risk_score": None},
            {"incident_id": "c", "title": "hero", "risk_level": "HIGH", "risk_score": 81.9, "details": {"event_count": 144, "affected_resources": ["/a", "/b", "/c", "/d"]}}]
    cards = vm.incident_cards(incs, [{"incident_id": "c", "priority": "P2", "contains_synthetic_data": True}])
    assert [c["incident_id"] for c in cards] == ["c", "a", "b"]
    assert cards[0]["has_alert"] and cards[0]["priority"] == "P2" and cards[0]["contains_synthetic"] and len(cards[0]["affected_resources"]) == 3
    assert cards[2]["risk_level"] == "NOT SCORED" and not cards[1]["has_alert"]


def test_risk_factor_rows_sorted_by_points_and_keep_finding_ids():
    risk = {"factors": [{"factor": "a", "points": 5, "weight": 5, "value": 1.0, "status": "observed"},
                        {"factor": "b", "points": 20, "weight": 20, "value": 1.0, "status": "observed", "finding_ids": ["fnd_1"]}]}
    rows = vm.risk_factor_rows(risk)
    assert [r["factor"] for r in rows] == ["b", "a"] and rows[0]["finding_ids"] == ["fnd_1"]
    assert vm.risk_factor_rows(None) == []


def test_evidence_gaps_distinguish_deterministic_from_ai_missing_evidence():
    out = _outcome()
    risk = make_incident()["details"]["risk"]
    rows = vm.evidence_gap_rows(risk, out["investigation"])
    sources = {r["source"] for r in rows}
    assert sources == {"deterministic", "ai_agent"} and all(r["evidence_type"] == "missing_evidence" for r in rows)
    assert any("account takeover" in r["text"] and "Why it matters" in r["text"] for r in rows if r["source"] == "ai_agent")
    assert vm.evidence_gap_rows(None, None) == []


def test_timeline_rows_label_every_entry_and_keep_traceability():
    tl = make_timeline() + [{"timestamp": "2026-10-03T10:40:00+00:00", "evidence_type": "ai_inference", "label": "AI", "event_ids": ["e1", "e2", "e3", "e4"], "event_ids_truncated": True}]
    rows = vm.timeline_rows(tl)
    assert rows[0]["event_ids"] == ["e1"] and rows[0]["event_count"] == 126 and rows[0]["evidence_label"] == "Observed fact"
    assert rows[-1]["evidence_label"].startswith("AI inference") and rows[-1]["event_ids_short"] == "e1, e2, e3 (+1 more)" and rows[-1]["event_ids_truncated"]
    assert vm.timeline_rows(None) == []


def test_investigation_view_separates_facts_from_inference():
    v = vm.investigation_view(_outcome()["investigation"])
    assert v["available"] and v["status"] == "ok"
    assert v["facts"] and all(f["evidence_type"] in ("observed", "derived_metric") for f in v["facts"])
    assert v["hypothesis"]["statement"] and v["hypothesis"]["confidence"] <= v["hypothesis"]["model_confidence"]
    assert v["claims"] and all(c["event_ids"] or c["refs"] for c in v["claims"])
    assert v["missing_evidence"] and v["alternatives"] and v["validation"]["hypothesis_grounded"] is True
    # facts never contain model-authored claims
    assert not ({c["claim"] for c in v["claims"]} & {f["text"] for f in v["facts"]})


def test_investigation_view_handles_not_run_and_failed_runs():
    v = vm.investigation_view({"status": "not_run", "notes": ["n"]})
    assert v["available"] is False and v["status"] == "not_run" and v["hypothesis"] is None and v["notes"] == ["n"]
    assert vm.investigation_view(None)["status"] == "not_run"
    failed = vm.investigation_view({"status": "llm_unavailable", "error": {"kind": "no_key"}, "facts": [{"evidence_type": "observed", "text": "x", "refs": []}]})
    assert failed["available"] is False and failed["status"] == "llm_unavailable" and failed["facts"][0]["label"] == "Observed fact"


def test_recommendation_rows_default_to_human_approval_and_not_executed():
    rows = vm.recommendation_rows(_outcome()["recommendations"])
    assert [r["priority"] for r in rows] == [1, 2]
    assert all(r["requires_human_approval"] is True and r["executed"] is False and r["status"] == "proposed" for r in rows)
    bare = vm.recommendation_rows({"recommendations": [{"action": "monitor", "priority": 1}]})
    assert bare[0]["requires_human_approval"] is True and bare[0]["executed"] is False
    assert vm.recommendation_rows(None) == []


def test_ti_rows_apply_the_no_evidence_rule_and_label_synthetic_data():
    none = vm.ti_rows({"status": "ok", "results": [{"indicator_type": "ip", "indicator": "203.0.113.5", "provider": "otx", "status": "no_evidence", "summary": "No threat-intelligence evidence was found"}]})
    assert "neither a sign of safety nor of maliciousness" in none["banner"] and none["evidence_found"] == 0
    synth = vm.ti_rows({"status": "ok", "results": [{"indicator_type": "ip", "indicator": "x", "provider": "synthetic_demo", "status": "evidence_found", "synthetic": True}]})
    assert "SYNTHETIC" in synth["banner"] and synth["has_synthetic"] and synth["evidence_found"] == 1
    real = vm.ti_rows({"status": "ok", "results": [{"indicator": "x", "status": "evidence_found", "provider": "otx"}]})
    assert real["banner"] is None
    nr = vm.ti_rows({"status": "not_run", "results": []})
    assert nr["banner"] is None and nr["status"] == "not_run" and nr["rows"] == []


GRAPH = {"nodes": [{"id": "ip:1", "type": "source_ip", "label": "1", "event_count": 2, "event_ids": ["e1", "e2"], "layer": 0},
                   {"id": "sess:s", "type": "session", "label": "s", "event_count": 1, "event_ids": ["e2"], "layer": 1},
                   {"id": "g001", "type": "event_group", "label": "126 failed logins", "event_count": 1, "event_ids": ["e1"], "layer": 2, "evidence_type": "observed", "stage_labels": ["Credential attack"]},
                   {"id": "g002", "type": "event_group", "label": "login", "event_count": 1, "event_ids": ["e2"], "layer": 2},
                   {"id": "inc:i", "type": "incident", "label": "Incident", "event_count": 2, "event_ids": ["e1", "e2"], "layer": 3}],
         "edges": [{"id": "e001", "source": "ip:1", "target": "sess:s", "relationship": "used_session", "evidence_type": "observed", "event_ids": ["e2"]},
                   {"id": "e002", "source": "g001", "target": "inc:i", "relationship": "contributes_to", "evidence_type": "derived_indicator", "event_ids": ["e1"]},
                   {"id": "e003", "source": "g001", "target": "ghost", "relationship": "x", "event_ids": []}]}


def test_graph_layout_is_layered_deterministic_and_traceable():
    a, b = vm.graph_layout(GRAPH), vm.graph_layout(GRAPH)
    assert a == b
    shuffled = {**GRAPH, "nodes": list(reversed(GRAPH["nodes"]))}   # layout must not depend on API ordering
    assert {n["id"]: (n["x"], n["y"]) for n in vm.graph_layout(shuffled)["nodes"]} == {n["id"]: (n["x"], n["y"]) for n in a["nodes"]}
    pos = {n["id"]: (n["x"], n["y"]) for n in a["nodes"]}
    assert pos["ip:1"][0] < pos["sess:s"][0] < pos["g001"][0] < pos["inc:i"][0]
    assert pos["g001"][0] == pos["g002"][0] and pos["g001"][1] < pos["g002"][1]  # stable order inside a layer (by type, time, id)
    assert pos["g001"][1] != pos["g002"][1] and abs(pos["g001"][1] + pos["g002"][1]) < 1e-9  # centred
    assert a["dropped_edges"] == 1 and len(a["edges"]) == 2 and all(e["event_ids"] for e in a["edges"])
    e = next(e for e in a["edges"] if e["id"] == "e002")
    assert (e["x0"], e["y0"]) == pos["g001"] and (e["x1"], e["y1"]) == pos["inc:i"]
    assert all(n["event_ids"] for n in a["nodes"])
    assert vm.graph_layout(None) == {"nodes": [], "edges": [], "dropped_edges": 0}


def test_error_banner_never_echoes_markdown_or_unknown_kinds():
    assert "unreachable" in vm.error_banner("backend_down")
    assert "Facts, risk, threat intelligence and the alert are still shown" in vm.error_banner("llm_unavailable")
    assert vm.error_banner("weird") == "Something went wrong."
    assert "<b>" not in vm.error_banner("database", "<b>boom</b>").replace("\\<b\\>", "")


if __name__ == "__main__":  # python -m tests.test_dashboard_viewmodels
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(exc))
    print("failures:", fails)
    sys.exit(1 if fails else 0)
