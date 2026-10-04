"""Pure-engine tests: determinism, gating, no over-merging, attack sequence, incident threshold."""
import random

import pytest

from app.correlation.config import defaults
from app.correlation.engine import FindingView, correlate, detect_stages
from app.detection.config import get_detection_config
from app.detection.rules import evaluate
from tests.helpers import failures, mk


def views(events):
    """Findings from the REAL rule engine, adapted to the engine's input type."""
    return [FindingView(f"fnd_{i}", d.event_id, "rule_engine", d.finding_type, d.confidence, d.rule_id,
                        d.evidence["category"], d.evidence["rule_title"], tuple(d.evidence["event_ids"]))
            for i, d in enumerate(evaluate(events, get_detection_config()))]


def hero(ip="203.0.113.10", t0=0.0):
    """Failed-login burst -> success -> new session -> sensitive access -> SQLi request (+ WAF)."""
    ev = failures(12, t0, 1.0, ip=ip, users=list("abcdef"), sid="pre")
    ev += [mk("login_success", t0 + 30, ip=ip, sid="pre", uid="victim", ep="/api/login", status=200, source="auth", method="POST"),
           mk("session_created", t0 + 40, ip=ip, sid="auth", uid="victim", source="auth"),
           mk("api_access", t0 + 45, ip=ip, sid="auth", uid="victim", ep="/api/account/me", status=200, source="api", method="GET"),
           mk("sensitive_endpoint_access", t0 + 50, ip=ip, sid="auth", uid="victim", ep="/api/admin/export", status=200, source="api", method="GET"),
           mk("http_request", t0 + 55, ip=ip, sid="auth", uid="victim", ep="/api/search?q=1 UNION SELECT NULL--", status=500, source="api", method="GET"),
           mk("waf_alert", t0 + 55.4, ip=ip, sid="auth", uid="victim", ep="/api/search", status=500, source="waf", method="GET")]
    return ev


def test_empty_and_findingless_input_gives_no_clusters():
    assert correlate([], [], defaults()).clusters == []
    benign = [mk("page_view", i * 5, ep="/", attrs={"page_seq": i}) for i in range(5)]
    r = correlate(benign, views(benign), defaults())
    assert r.clusters == [] and r.seed_events == 0 and r.events_considered == 5


def test_hero_chain_becomes_one_cluster_with_all_stages_and_post_login_context():
    ev = hero()
    vs = views(ev)
    r = correlate(ev, vs, defaults())
    assert len(r.clusters) == 1
    c = r.clusters[0]
    assert len(c.event_ids) == len(ev)                                  # post-login events (no finding) joined by IP/user
    assert list(c.stages) == ["credential_attack", "authentication_success", "new_session", "sensitive_access", "attack_indicator"]
    assert c.link_counts()["attack_sequence"] == 4 and c.is_incident_candidate
    assert c.title.startswith("Suspicious activity chain from 203.0.113.10: failed-login burst")
    assert c.affected_resources == ["/api/admin/export", "/api/search"]  # paths only - never query strings


def test_links_are_ordered_in_time_and_bounded():
    ev = hero()
    c = correlate(ev, views(ev), defaults()).clusters[0]
    ts = {e.event_id: e.timestamp for e in ev}
    assert all(ts[l.event_id] <= ts[l.related_event_id] for l in c.links)
    assert all(0 <= l.strength <= 1 for l in c.links)
    assert len(c.links) <= defaults()["max_links_per_cluster"]
    assert len(set(c.links)) == len(c.links)


def test_result_is_deterministic_and_independent_of_input_order():
    ev = hero() + hero(ip="198.51.100.9", t0=5000)
    vs = views(ev)
    a = correlate(ev, vs, defaults())
    shuffled = ev[:]
    random.Random(7).shuffle(shuffled)
    b = correlate(shuffled, list(reversed(vs)), defaults())
    sig = lambda r: [(c.cluster_id, c.event_ids, c.links, c.title, c.stages) for c in r.clusters]  # noqa: E731
    assert sig(a) == sig(b) and len(a.clusters) == 2


def test_time_gap_splits_actions_by_the_same_ip():
    ev = failures(12, 0, 1.0, users=list("abcdef"), sid="s1") + failures(12, 5000, 1.0, users=list("abcdef"), sid="s2")
    r = correlate(ev, views(ev), defaults())
    assert len(r.clusters) == 2                                         # > max_gap_s apart, different sessions


def test_failed_login_does_not_link_by_user_so_a_guessed_account_is_not_merged():
    """The attacker guesses account 'victim' from IP A. The real user logs in from IP B with their own session.
    A failed attempt names an account, it does not identify a user, so the two must stay unrelated."""
    attack = failures(12, 0, 1.0, ip="203.0.113.10", users=["victim"], sid="atk")
    real = [mk("login_success", 20, ip="192.0.2.77", sid="real", uid="victim", ep="/api/login", status=200, source="auth", method="POST"),
            mk("page_view", 25, ip="192.0.2.77", sid="real", uid="victim", ep="/account", attrs={"page_seq": 1})]
    r = correlate(attack + real, views(attack + real), defaults())
    assert len(r.clusters) == 1
    assert r.clusters[0].source_ips == ["203.0.113.10"] and not any(e.event_id in r.clusters[0].event_ids for e in real)


def test_same_endpoint_and_similar_behavior_never_merge_two_actors():
    sqli = lambda ip, sid, t: mk("http_request", t, ip=ip, sid=sid, ep="/products?id=1 UNION SELECT NULL--", status=500, source="app", method="GET")  # noqa: E731
    ev = [sqli("203.0.113.1", "a", 0), sqli("203.0.113.2", "b", 5)]     # same path + same finding category, different actors
    r = correlate(ev, views(ev), defaults())
    assert len(r.clusters) == 2


def test_same_endpoint_is_recorded_inside_a_cluster():
    ev = hero()
    c = correlate(ev, views(ev), defaults()).clusters[0]
    assert c.link_counts().get("same_endpoint", 0) >= 1 and "same_ip" in c.link_counts() and "same_session" in c.link_counts()
    # the 12 repeated failed logins (same type + session + path) do not produce 11 redundant same_endpoint records
    assert c.link_counts()["same_endpoint"] < 6


def test_strength_decreases_with_gap_and_follows_documented_formula():
    cfg = defaults()
    ev = [mk("http_request", 0, sid="s", ep="/a?x=<script>alert(1)</script>", source="app", method="GET"),
          mk("http_request", 10, sid="s", ep="/b", source="app", method="GET"),
          mk("http_request", 10 + 900, sid="s", ep="/c", source="app", method="GET")]
    c = correlate(ev, views(ev), cfg).clusters[0]
    ip_links = sorted((l for l in c.links if l.relationship_type == "same_ip"), key=lambda l: l.strength, reverse=True)
    assert [l.strength for l in ip_links] == [round(0.6 * (1 - 0.5 * 10 / 900), 3), round(0.6 * (1 - 0.5 * 900 / 900), 3)]


def test_incident_threshold_low_confidence_single_category_is_a_cluster_not_an_incident():
    ev = [mk("page_view", i * 1.0, ep=p, attrs={"page_seq": i + 1}) for i, p in enumerate(["/admin", "/wp-admin", "/.env"])]
    vs = views(ev)
    assert [v.rule_id for v in vs] == ["R-BEH-004"]                     # confidence 0.45, one category
    r = correlate(ev, vs, defaults())
    assert len(r.clusters) == 1 and r.clusters[0].is_incident_candidate is False
    cfg = defaults()
    cfg.data["incident"]["min_max_finding_confidence"] = 0.4
    assert correlate(ev, vs, cfg).clusters[0].is_incident_candidate is True


def test_ordinary_login_and_new_session_are_not_labelled_as_attack_stages():
    ev = [mk("login_success", 0, uid="u", ep="/api/login", status=200, source="auth", method="POST"),
          mk("session_created", 5, sid="s2", uid="u", source="auth"),
          mk("http_request", 20, sid="s2", uid="u", ep="/p?id=1 UNION SELECT NULL--", status=500, source="app", method="GET")]
    stages = detect_stages(ev, views(ev))
    assert "credential_attack" not in stages                            # no failed-login burst in this cluster


def test_attack_sequence_requires_the_same_actor():
    atk = failures(12, 0, 1.0, ip="203.0.113.10", users=list("abcdef"), sid="pre")
    other = [mk("login_success", 20, ip="198.51.100.5", sid="x", uid="someone", ep="/api/login", status=200, source="auth", method="POST")]
    c = correlate(atk + other, views(atk + other), defaults()).clusters[0]
    assert "attack_sequence" not in c.link_counts()


@pytest.mark.parametrize("bad", [{"merge_types": ["nope"]}, {"base_strength": {"same_ip": 2}}, {"max_gap_s": {"same_ip": 0}}])
def test_config_validation_rejects_bad_values(bad):
    from app.correlation.config import _deep_merge, DEFAULTS, validate
    assert validate(_deep_merge(DEFAULTS, bad))
