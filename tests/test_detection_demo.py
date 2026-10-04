"""End-to-end: synthetic demo data -> real pipeline -> rules -> labelled evaluation (PRD section 39)."""
from sqlalchemy import select

from app.database import database
from app.database.models import Event, Finding, Website
from app.demo.loader import load_scenario
from app.detection.config import defaults
from app.detection.engine import run_detection
from app.detection.evaluation import evaluate_against_labels, flagged_event_ids


def _setup(client, auth_a, site_a):
    return site_a["website"]["website_id"]


def _rules_for(db, scenario_event_ids):
    out = {}
    for f in db.scalars(select(Finding).where(Finding.event_id.in_(scenario_event_ids))):
        out.setdefault(f.evidence["rule_id"], []).append(f)
    return out


def test_all_demo_scenarios_zero_false_positives_and_every_attack_found(client, auth_a, site_a):
    w = _setup(client, auth_a, site_a)
    with database.SessionLocal() as db:
        site = db.get(Website, w)
        loaded = load_scenario(db, site, "all")
        assert len(loaded["labels"]) == loaded["loaded"] == 9518                  # a label for every single event
        res = run_detection(db, w)
        ev = evaluate_against_labels(db, w, loaded["labels"])

        assert ev["false_positive"] == 0 and ev["precision"] == 1.0, ev["false_positive_examples"]
        for scenario, s in ev["scenarios"].items():
            assert s["has_finding"] == (s["label"] == "malicious"), scenario        # benign + hard negatives silent, attacks found
        assert ev["scenarios"]["benign_failed_logins"]["flagged"] == 0 and ev["scenarios"]["normal_traffic"]["flagged"] == 0
        assert res.events_analyzed == 9518 and 0 < res.suspicious_events <= 455
        # the controlled funnel is a TARGET only; here we just assert the reduction is real, not the PRD's exact numbers
        assert res.findings_created < 50 and res.finding_anchor_events < res.suspicious_events < res.events_analyzed


def test_hero_chain_is_reconstructable_from_rule_findings(client, auth_a, site_a):
    w = _setup(client, auth_a, site_a)
    with database.SessionLocal() as db:
        site = db.get(Website, w)
        loaded = load_scenario(db, site, "all")
        run_detection(db, w)
        hero_ids = [e for e, v in loaded["labels"].items() if v["scenario"] == "hero_credential_abuse"]
        by_rule = _rules_for(db, hero_ids)
        assert {"R-AUTH-001", "R-AUTH-002", "R-AUTH-003", "R-ATK-001", "R-WAF-001", "R-BEH-002", "R-BEH-003", "R-BEH-004"} <= set(by_rule)

        burst = by_rule["R-AUTH-001"][0].evidence                                     # PRD: "126 failed login attempts in 18 seconds"
        assert burst["observed"]["failed_login_count"] == 126 and burst["observed"]["duration_s"] == 18.0
        assert len(burst["event_ids"]) == 126 and set(burst["event_ids"]) <= set(hero_ids)

        success = by_rule["R-AUTH-003"][0]
        assert success.evidence["observed"]["account_was_targeted_in_burst"] is True and success.confidence == 0.9
        assert db.get(Event, success.event_id).event_type == "login_success"
        sqli = by_rule["R-ATK-001"][0]
        assert "UNION" in db.get(Event, sqli.event_id).endpoint.upper().replace("+", " ") and db.get(Event, sqli.event_id).status_code == 500
        # chronological order of the detected stages matches the PRD hero chain
        t = lambda f: db.get(Event, f.event_id).timestamp  # noqa: E731
        assert t(by_rule["R-BEH-003"][0]) < t(by_rule["R-AUTH-001"][0]) < t(success) < t(sqli)


def test_injection_probe_and_bot_scraper_findings(client, auth_a, site_a):
    w = _setup(client, auth_a, site_a)
    with database.SessionLocal() as db:
        site = db.get(Website, w)
        loaded = load_scenario(db, site, "all")
        run_detection(db, w)
        probe = _rules_for(db, [e for e, v in loaded["labels"].items() if v["scenario"] == "injection_probe"])
        assert {"R-ATK-001", "R-ATK-002", "R-ATK-003", "R-ATK-004", "R-ATK-005", "R-WAF-001"} <= set(probe)
        assert probe["R-ATK-005"][0].evidence["derived_metrics"]["distinct_categories"] == 4
        bot = _rules_for(db, [e for e, v in loaded["labels"].items() if v["scenario"] == "bot_scraper"])
        assert {"R-BEH-001", "R-BEH-002"} <= set(bot) and bot["R-BEH-002"][0].evidence["observed"]["user_agent_class"] == "automation_tool"


def test_ablation_hero_coverage_does_not_depend_on_user_agent_rule(client, auth_a, site_a):
    """Guards against inflated metrics: the synthetic attacker keeps one headless UA, so R-BEH-002 alone can
    'flag' every attack event. Without it the hero chain must still be found by behavioural/auth/attack rules."""
    w = _setup(client, auth_a, site_a)
    cfg = defaults()
    cfg.data["rules"]["R-BEH-002"]["enabled"] = False
    with database.SessionLocal() as db:
        site = db.get(Website, w)
        loaded = load_scenario(db, site, "all")
        run_detection(db, w, cfg=cfg)
        ev = evaluate_against_labels(db, w, loaded["labels"])
        assert ev["false_positive"] == 0
        hero = ev["scenarios"]["hero_credential_abuse"]
        assert hero["has_finding"] and hero["flagged"] / hero["events"] >= 0.9
        assert ev["scenarios"]["bot_scraper"]["has_finding"] and ev["scenarios"]["injection_probe"]["flagged"] == 11
        # honest recall: contextual events (post-login API calls etc.) are left to correlation (milestone 5)
        assert ev["recall"] < 1.0


def test_demo_run_is_reproducible(client, auth_a, site_a):
    w = _setup(client, auth_a, site_a)
    with database.SessionLocal() as db:
        load_scenario(db, db.get(Website, w), "all")
        r1, r2 = run_detection(db, w), run_detection(db, w)
        assert r1.by_rule == r2.by_rule and r1.suspicious_events == r2.suspicious_events and r2.findings_replaced == r1.findings_created
        anchors, flagged, _ = flagged_event_ids(db, w)
        assert len(anchors) == r1.finding_anchor_events and len(flagged) == r1.suspicious_events
