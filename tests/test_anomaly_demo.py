"""Behaviour on the committed SYNTHETIC demo data. HONESTY NOTE: thresholds were chosen while looking at this
data, so this shows the model behaves as designed on controlled data, not real-world accuracy."""
import copy

import pytest

from app.ml.anomaly_model import analyze_events
from app.ml.config import AnomalyConfig, defaults
from tests.anomaly_helpers import load_demo_events


@pytest.fixture(scope="module")
def demo():
    events, truth = load_demo_events()
    return events, truth


def test_flags_the_high_volume_attack_sessions_and_no_benign_session(demo):
    events, truth = demo
    rep = analyze_events(events)
    assert rep.status == "ok" and rep.sessions_analyzed == 674
    assert sorted(rep.flagged_sessions) == ["sess-bot-1", "sess-h-pre"]
    for key in rep.flagged_sessions:
        assert truth[key][1] == "malicious"
    benign_flagged = [k for k in rep.flagged_sessions if truth[k][1] != "malicious"]
    assert benign_flagged == []


def test_hard_negatives_are_scored_high_but_not_flagged(demo):
    """Mistyped-password sessions are structurally rare (isolation score is high) but only mildly deviant: the
    deviation gate is what keeps them out. This is the reason the model needs two signals."""
    events, truth = demo
    rep = analyze_events(events)
    typo = [s for s in rep.scores if s.key.startswith("sess-typo")]
    assert len(typo) == 8 and not any(s.flagged for s in typo)
    assert max(s.anomaly_score for s in typo) >= 0.65 and max(s.max_deviation_z for s in typo) < 8


def test_hero_session_explanation_names_the_failed_login_burst(demo):
    events, _ = demo
    d = next(d for d in analyze_events(events).drafts if d.evidence["observed"]["session_key"] == "sess-h-pre")
    devs = {x["feature"]: x for x in d.evidence["derived_metrics"]["notable_deviations"]}
    assert "login_failures" in devs and devs["login_failures"]["value"] == 126 and devs["login_failures"]["baseline_median"] == 0


def test_documented_limitation_low_volume_attacks_are_not_behaviourally_anomalous(demo):
    """The 11-request SQLi probe and the 7-event post-login session look ordinary at session level. They are
    covered by the attack-indicator rules / correlation (M5), not by this model. Asserted so the README claim
    cannot silently drift from reality."""
    events, _ = demo
    flagged = set(analyze_events(events).flagged_sessions)
    assert "sess-probe-1" not in flagged and "sess-h-auth" not in flagged


def test_stable_across_seeds(demo):
    events, _ = demo
    for seed in (0, 1, 2, 3, 4, 5):
        data = copy.deepcopy(defaults().data)
        data["model"]["random_state"] = seed
        assert sorted(analyze_events(events, AnomalyConfig(data=data)).flagged_sessions) == ["sess-bot-1", "sess-h-pre"], seed


def test_session_level_evaluation_metrics(demo):
    from app.ml.evaluation import evaluate_sessions
    events, truth = demo
    rep = analyze_events(events)
    ev = evaluate_sessions(rep, {k: {"scenario": s, "label": lab} for k, (s, lab) in truth.items()})
    assert ev["sessions_evaluated"] == 674 and ev["malicious_sessions"] == 4 and ev["benign_sessions"] == 670
    assert ev["true_positive"] == 2 and ev["false_positive"] == 0 and ev["false_negative"] == 2
    assert ev["precision"] == 1.0 and ev["recall"] == 0.5
    assert ev["missed_malicious_sessions"] == ["sess-h-auth", "sess-probe-1"]       # the documented, by-design misses
    assert ev["malicious_scenarios"]["bot_scraper"] == {"sessions": 1, "flagged": 1}
    assert ev["malicious_scenarios"]["injection_probe"] == {"sessions": 1, "flagged": 0}
    assert "not a real-world accuracy claim" in ev["caveat"].lower()


def test_evaluation_of_unrun_report_is_safe():
    from app.ml.anomaly_model import AnomalyReport
    from app.ml.evaluation import evaluate_sessions
    ev = evaluate_sessions(AnomalyReport(status="insufficient_baseline"), {"s": {"scenario": "x", "label": "malicious"}})
    assert ev["status"] == "insufficient_baseline" and ev["sessions_evaluated"] == 0 and ev["recall"] == 0.0
