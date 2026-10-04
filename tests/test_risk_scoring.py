"""Pure scoring tests: no DB, no LLM, no network (PRD section 17, 19, 35; AC-16)."""
import copy
from dataclasses import replace

import pytest

from app.correlation.engine import STAGE_ORDER
from app.risk.config import DEFAULTS, RiskConfig, defaults
from app.risk.scoring import RiskFinding, RiskInputs, score_incident, stored_risk
from app.database.models import Incident


def F(fid, ftype, cat, conf, rule="R-X", agent="rule_engine", anomaly=None):
    return RiskFinding(fid, agent, ftype, cat, rule, conf, anomaly)


HERO_STAGES = {s: 1 for s in STAGE_ORDER}


def hero(**over):
    base = RiskInputs(
        findings=[F("f1", "auth_anomaly", "login_success_after_failure_burst", 0.9), F("f2", "attack_indicator", "sql_injection_indicator", 0.85),
                  F("f3", "behavior_anomaly", "non_human_navigation", 0.7), F("f4", "ml_anomaly", "ml_session_anomaly", 0.8, agent="anomaly_model", anomaly=0.8)],
        stages=dict(HERO_STAGES), event_count=144, link_count=300, mean_link_strength=0.75,
        affected_resources=["/api/admin/customers/export"])
    return replace(base, **over)


def cfg_with(**changes) -> RiskConfig:
    d = copy.deepcopy(DEFAULTS)
    for k, v in changes.items():
        d[k] = {**d[k], **v} if isinstance(v, dict) else v
    return RiskConfig(data=d)


def fac(res, name):
    return next(f for f in res["factors"] if f["factor"] == name)


def test_deterministic_and_complete():
    a, b = score_incident(hero(), defaults()), score_incident(hero(), defaults())
    assert a == b
    assert {f["factor"] for f in a["factors"]} == set(DEFAULTS["weights"])
    assert 0 <= a["risk_score"] <= 100 and 0 <= a["confidence"] <= 1
    assert a["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert abs(sum(f["points"] for f in a["factors"]) - a["risk_score"]) < 0.1     # factor points explain the score
    assert a["config"]["fingerprint"] == defaults().fingerprint and a["basis"] == "config_driven_scoring"


def test_hero_chain_scores_high_and_empty_incident_scores_low():
    h = score_incident(hero())
    assert h["risk_level"] in ("HIGH", "CRITICAL")
    empty = score_incident(RiskInputs())
    assert empty["risk_level"] == "LOW" and empty["risk_score"] < 5 and empty["confidence"] == 0.0


def test_every_factor_is_traceable_and_labelled():
    for f in score_incident(hero())["factors"]:
        assert f["basis"] and f["evidence_type"] == "derived_metric" and 0 <= f["value"] <= 1
    r = score_incident(hero())
    assert fac(r, "authentication")["finding_ids"] == ["f1"] and fac(r, "attack_indicators")["finding_ids"] == ["f2"]
    assert fac(r, "sensitive_endpoint")["stages"] == ["sensitive_access", "authentication_success"]
    assert {s["finding_id"] for s in r["supporting_findings"]} == {"f1", "f2", "f3", "f4"}


def test_weights_drive_the_score_and_zero_weight_removes_a_factor():
    base = score_incident(hero())
    heavier = score_incident(hero(), cfg_with(weights={"authentication": 80}))
    assert heavier["risk_score"] > base["risk_score"]
    no_auth = score_incident(hero(), cfg_with(weights={"authentication": 0}))
    assert fac(no_auth, "authentication")["points"] == 0
    only = score_incident(hero(), cfg_with(weights={k: (1 if k == "asset_impact" else 0) for k in DEFAULTS["weights"]}))
    assert only["risk_score"] == 100.0           # asset value 1.0 is the only factor counted


def test_levels_use_configured_thresholds():
    r = score_incident(hero())
    s = r["risk_score"]
    assert score_incident(hero(), cfg_with(levels={"medium": 1, "high": 2, "critical": s - 0.05}))["risk_level"] == "CRITICAL"
    assert score_incident(hero(), cfg_with(levels={"medium": 1, "high": s - 0.05, "critical": 99}))["risk_level"] == "HIGH"
    assert score_incident(hero(), cfg_with(levels={"medium": s - 0.05, "high": 98, "critical": 99}))["risk_level"] == "MEDIUM"
    assert score_incident(hero(), cfg_with(levels={"medium": 98, "high": 99, "critical": 100}))["risk_level"] == "LOW"


def test_absence_never_lowers_risk_and_is_reported_as_a_gap():
    with_ti_not_run = score_incident(hero())
    ti_none = score_incident(hero(threat_intel={"status": "ok", "results": [{"indicator_type": "ip", "status": "no_evidence", "synthetic": False}]}))
    assert fac(with_ti_not_run, "threat_intel")["status"] == "not_assessed" and fac(ti_none, "threat_intel")["status"] == "no_evidence"
    assert with_ti_not_run["risk_score"] == ti_none["risk_score"]            # no evidence adds 0, never subtracts
    assert "safe" in fac(ti_none, "threat_intel")["basis"] and "not a claim" in fac(ti_none, "threat_intel")["basis"]
    gaps = {g["gap"] for g in with_ti_not_run["evidence_gaps"]}
    assert {"threat_intel_not_run", "no_asset_context"} <= gaps
    assert "no_threat_intel_evidence" in {g["gap"] for g in ti_none["evidence_gaps"]}
    assert "no_ml_anomaly" in {g["gap"] for g in score_incident(hero(findings=hero().findings[:3]))["evidence_gaps"]}


def ti(*results, status="ok"):
    return {"status": status, "results": list(results), "retrieved_at": "2026-10-03T10:00:00+00:00"}


def res(t="ip", status="evidence_found", synthetic=False):
    return {"indicator_type": t, "indicator": "x", "status": status, "synthetic": synthetic}


def test_real_ti_evidence_raises_risk_and_confidence_synthetic_does_not():
    base = score_incident(hero())
    real = score_incident(hero(threat_intel=ti(res())))
    synth = score_incident(hero(threat_intel=ti(res(synthetic=True))))
    assert real["risk_score"] > base["risk_score"] and real["confidence"] >= base["confidence"]
    assert fac(real, "threat_intel")["value"] == 0.7
    assert synth["risk_score"] == base["risk_score"] and fac(synth, "threat_intel")["status"] == "excluded"
    assert "SYNTHETIC" in fac(synth, "threat_intel")["basis"]
    counted = score_incident(hero(threat_intel=ti(res(synthetic=True))), cfg_with(threat_intel={"count_synthetic": True}))
    assert counted["risk_score"] > base["risk_score"]


def test_mitre_context_and_failed_lookups_are_not_evidence():
    r = score_incident(hero(threat_intel=ti(res("attack_technique"), res(status="error"), res(status="rate_limited"), res(status="not_applicable"), status="partial")))
    assert fac(r, "threat_intel")["value"] == 0 and r["risk_score"] == score_incident(hero())["risk_score"]
    two = score_incident(hero(threat_intel=ti(res(), res("cve"))))
    assert fac(two, "threat_intel")["value"] == pytest.approx(0.85)
    many = score_incident(hero(threat_intel=ti(*[res() for _ in range(9)])))
    assert fac(many, "threat_intel")["value"] == 1.0                           # clamped


def test_confidence_is_separate_from_risk():
    # a heavy asset weight changes risk a lot but cannot change the evidence-support index
    a = score_incident(hero(), cfg_with(weights={"asset_impact": 1}))
    b = score_incident(hero(), cfg_with(weights={"asset_impact": 500}))
    assert a["risk_score"] != b["risk_score"] and a["confidence"] == b["confidence"]
    # a single weak signal: low support even though the risk factor can be high
    one = score_incident(RiskInputs(findings=[F("f", "attack_indicator", "sql_injection_indicator", 0.4)], event_count=1))
    assert one["confidence"] < score_incident(hero())["confidence"]
    assert one["confidence_components"]["signal_diversity"]["distinct_signal_kinds"] == 1


def test_truncation_lowers_confidence_and_is_a_gap():
    a, b = score_incident(hero()), score_incident(hero(truncated=True))
    assert b["confidence"] == pytest.approx(a["confidence"] - 0.1, abs=0.011) and b["risk_score"] == a["risk_score"]
    assert "truncated_evidence" in {g["gap"] for g in b["evidence_gaps"]}


def test_synthetic_flag_is_surfaced():
    r = score_incident(hero(all_events_synthetic=True))
    assert r["contains_synthetic_data"] is True and "synthetic_data" in {g["gap"] for g in r["evidence_gaps"]}
    assert score_incident(hero())["contains_synthetic_data"] is False


def test_asset_impact_longest_prefix_and_boundaries():
    v = lambda *paths: fac(score_incident(hero(affected_resources=list(paths))), "asset_impact")["value"]  # noqa: E731
    assert v("/api/admin/users") == 1.0 and v("/api/account/profile") == 0.7 and v("/api/search") == 0.4
    assert v("/api/account/payment-methods/1") == 1.0         # longest prefix beats /api/account
    assert v("/products") == 0.2                              # default for unmatched
    assert v("/administrator") == 0.2                         # prefix match respects the segment boundary
    assert v("/api/admin?x=1") == 1.0                         # query string ignored
    assert v("/products", "/admin") == 1.0                    # highest of the affected resources
    assert fac(score_incident(hero(affected_resources=[])), "asset_impact")["status"] == "not_observed"


def test_attack_breadth_bonus_and_auth_categories():
    one = RiskInputs(findings=[F("a", "attack_indicator", "sql_injection_indicator", 0.7)])
    many = RiskInputs(findings=[F("a", "attack_indicator", "sql_injection_indicator", 0.7), F("b", "attack_indicator", "xss_indicator", 0.6),
                                F("c", "attack_indicator", "ssrf_indicator", 0.6)])
    assert fac(score_incident(one), "attack_indicators")["value"] == 0.7
    assert fac(score_incident(many), "attack_indicators")["value"] == pytest.approx(0.9)
    brute = RiskInputs(findings=[F("a", "auth_anomaly", "brute_force_indicator", 0.99)])
    succ = RiskInputs(findings=[F("a", "auth_anomaly", "login_success_after_failure_burst", 0.5)])
    assert fac(score_incident(brute), "authentication")["value"] == 0.5          # configured category value, not the rule confidence
    assert fac(score_incident(succ), "authentication")["value"] == 1.0
    assert fac(score_incident(RiskInputs(findings=[F("a", "auth_anomaly", "some_new_category", 0.1)])), "authentication")["value"] == 0.5


def test_sensitive_endpoint_and_anomaly_normalisation():
    only_sens = RiskInputs(stages={"sensitive_access": 3})
    assert fac(score_incident(only_sens), "sensitive_endpoint")["value"] == 0.7
    assert fac(score_incident(RiskInputs(stages={"sensitive_access": 3, "authentication_success": 1})), "sensitive_endpoint")["value"] == 1.0
    assert fac(score_incident(RiskInputs()), "sensitive_endpoint")["status"] == "not_observed"
    for s, want in ((0.5, 0.0), (0.75, 0.5), (1.0, 1.0), (0.4, 0.0)):
        r = score_incident(RiskInputs(findings=[F("m", "ml_anomaly", "ml_session_anomaly", 0.7, agent="anomaly_model", anomaly=s)]))
        assert fac(r, "anomaly")["value"] == pytest.approx(want)
    # an ML finding without a score is not guessed at
    assert fac(score_incident(RiskInputs(findings=[F("m", "ml_anomaly", "ml_session_anomaly", 0.7, agent="anomaly_model")])), "anomaly")["status"] == "not_observed"


def test_behavior_factor_ignores_model_findings():
    r = score_incident(RiskInputs(findings=[F("m", "behavior_anomaly", "x", 0.9, agent="anomaly_model")]))
    assert fac(r, "behavior")["status"] == "not_observed"


def test_correlation_factor_grows_with_stages_size_and_strength():
    def c(**kw):
        return fac(score_incident(RiskInputs(**kw)), "correlation")["value"]
    assert c(event_count=0) == 0
    assert c(event_count=10, mean_link_strength=0.5) < c(event_count=100, mean_link_strength=0.5) < c(event_count=100, mean_link_strength=0.9)
    assert c(event_count=100, stages={"sensitive_access": 1}) < c(event_count=100, stages=dict(HERO_STAGES))
    assert c(event_count=10_000, stages=dict(HERO_STAGES), mean_link_strength=1.0) == pytest.approx(1.0)


def test_stored_risk_staleness_flags():
    inc = Incident(incident_id="i", website_id="w", title="t", details={"event_count": 5})
    assert stored_risk(inc)["status"] == "not_run"
    inc.details = {"event_count": 5, "risk": {"status": "ok", "scored_event_count": 5, "scored_threat_intel_at": None}}
    assert stored_risk(inc)["stale"] is False
    inc.details["event_count"] = 9
    r = stored_risk(inc)
    assert r["stale"] and "correlated events changed" in r["stale_reasons"][0]
    inc.details = {"event_count": 5, "risk": {"scored_event_count": 5, "scored_threat_intel_at": None}, "threat_intel": {"retrieved_at": "2026-10-03T10:00:00+00:00"}}
    assert stored_risk(inc)["stale"] is True
