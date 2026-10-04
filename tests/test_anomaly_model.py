import copy
import random
from unittest import mock

import pytest

from app.ml import anomaly_model
from app.ml.anomaly_model import AGENT_NAME, FINDING_TYPE, RULE_ID, analyze_events, confidence_for
from app.ml.config import AnomalyConfig, defaults
from tests.anomaly_helpers import attacker_events, baseline_events


def cfg_with(**over):
    data = copy.deepcopy(defaults().data)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(data.get(k), dict):
            data[k].update(v)
        else:
            data[k] = v
    return AnomalyConfig(data=data)


def test_flags_the_attacker_session_and_nothing_else():
    events = baseline_events(80) + attacker_events()
    rep = analyze_events(events)
    assert rep.status == "ok" and rep.sessions_analyzed == 81 and rep.training_sessions == 81
    assert rep.flagged_sessions == ["sess-attack"] and len(rep.drafts) == 1
    top = rep.scores[0]
    assert top.key == "sess-attack" and top.flagged and top.anomaly_score >= 0.65 and top.max_deviation_z >= 8
    assert top.deviations[0]["feature"] in ("login_failures", "requests_per_min", "distinct_failed_users")


def test_a_purely_normal_population_produces_no_findings():
    rep = analyze_events(baseline_events(120, seed=11))
    assert rep.status == "ok" and rep.drafts == []                       # the two-signal gate suppresses 'least normal' noise


def test_finding_is_traceable_and_separates_fact_from_inference():
    events = baseline_events(80) + attacker_events()
    attacker_ids = {e.event_id for e in events if e.session_id == "sess-attack"}
    d = analyze_events(events).drafts[0]
    assert d.finding_type == FINDING_TYPE == "ml_anomaly" and d.rule_id == RULE_ID and d.event_id in attacker_ids
    ev = d.evidence
    assert set(ev["event_ids"]) == attacker_ids and ev["event_ids_truncated"] is False   # every cited id is a real session event
    assert ev["observed"]["session_key"] == "sess-attack" and ev["observed"]["event_count"] == 105
    dm = ev["derived_metrics"]
    assert dm["anomaly_score"] >= 0.65 and dm["max_deviation_z"] >= 8 and dm["notable_deviations"]
    assert dm["model"]["type"] == "IsolationForest" and dm["model"]["n_training_sessions"] == 81
    assert ev["interpretation"]["basis"] == "model_output_template"                      # never an LLM, never proof
    assert "does not show that an attack occurred" in ev["interpretation"]["text"]
    assert any("not a probability" in x for x in ev["limitations"])
    assert ev["thresholds"]["score_threshold"] == 0.65 and ev["mitre_reference"] is None
    assert 0.5 <= d.confidence <= 0.9
    assert AGENT_NAME == "anomaly_model"


def test_result_is_deterministic_and_independent_of_input_order():
    events = baseline_events(80) + attacker_events()
    a = analyze_events(events)
    shuffled = events[:]
    random.Random(3).shuffle(shuffled)
    b = analyze_events(shuffled)
    assert a.flagged_sessions == b.flagged_sessions
    assert [(s.key, round(s.anomaly_score, 9)) for s in a.scores] == [(s.key, round(s.anomaly_score, 9)) for s in b.scores]
    assert [d.confidence for d in a.drafts] == [d.confidence for d in b.drafts]


def test_flag_is_stable_across_random_seeds():
    events = baseline_events(80) + attacker_events()
    for seed in range(5):
        assert analyze_events(events, cfg_with(model={"random_state": seed})).flagged_sessions == ["sess-attack"], seed


def test_both_signals_are_required_to_flag():
    events = baseline_events(80) + attacker_events()
    assert analyze_events(events, cfg_with(score_threshold=0.99)).drafts == []          # score signal not met
    assert analyze_events(events, cfg_with(min_deviation_z=10_000)).drafts == []        # deviation signal not met
    rep = analyze_events(events, cfg_with(score_threshold=0.5, min_deviation_z=10_000))
    assert rep.drafts == [] and rep.scores[0].anomaly_score >= 0.5                      # scores are still reported


def test_insufficient_baseline_reports_status_and_creates_nothing():
    rep = analyze_events(baseline_events(10) + attacker_events())
    assert rep.status == "insufficient_baseline" and rep.drafts == [] and rep.scores == [] and "50" in rep.error
    assert analyze_events([]).status == "insufficient_baseline"


def test_disabled_config():
    rep = analyze_events(baseline_events(80) + attacker_events(), cfg_with(enabled=False))
    assert rep.status == "disabled" and rep.drafts == []


def test_missing_scikit_learn_degrades_gracefully():
    with mock.patch.object(anomaly_model, "_load_isolation_forest", side_effect=anomaly_model.ModelUnavailable("scikit-learn is not installed")):
        rep = analyze_events(baseline_events(80) + attacker_events())
    assert rep.status == "model_unavailable" and "scikit-learn" in rep.error and rep.drafts == []


def test_unexpected_error_never_propagates():
    with mock.patch.object(anomaly_model, "build_matrix", side_effect=ValueError("boom")):
        rep = analyze_events(baseline_events(80) + attacker_events())
    assert rep.status == "error" and "ValueError" in rep.error and rep.drafts == []


def test_identical_sessions_do_not_crash_or_flag():
    rep = analyze_events([e for i in range(60) for e in _clone_session(i)])
    assert rep.status == "ok" and rep.drafts == []


def _clone_session(i):
    from datetime import timedelta
    from tests.anomaly_helpers import T0, make_event
    return [make_event("page_view", T0 + timedelta(seconds=10 * k), ip=f"192.0.2.{i + 1}", sid=f"c{i}", ep="/") for k in range(4)]


def test_confidence_mapping_is_bounded_and_monotonic():
    c = defaults()
    vals = [confidence_for(s, c) for s in (0.0, 0.65, 0.7, 0.8, 0.9, 1.0, 1.5)]
    assert vals == sorted(vals) and vals[0] == vals[1] == 0.5 and vals[-1] == vals[-2] == 0.9
    assert 0.5 < confidence_for(0.8, c) < 0.9


def test_report_dict_is_json_serialisable_and_carries_the_caveat():
    import json
    d = analyze_events(baseline_events(80) + attacker_events()).to_dict(top_n=3)
    json.dumps(d)
    assert d["status"] == "ok" and d["flagged_sessions"] == 1 and len(d["top_scored_sessions"]) == 3
    assert "not a probability" in d["note"]
