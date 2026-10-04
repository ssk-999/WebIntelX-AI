import pytest

from app.detection.config import defaults
from app.detection.rules import RULES, evaluate
from tests.helpers import HEADLESS, failures, mk, rules_of

CFG = defaults()


def run(events, cfg=CFG):
    return evaluate(events, cfg)


def only(drafts, rule_id):
    return [d for d in drafts if d.rule_id == rule_id]


# ------------------------------------------------------------------ authentication
def test_failed_login_burst_threshold_and_anchor():
    fs = failures(12, step=2)
    d = only(run(fs), "R-AUTH-001")
    assert len(d) == 1 and d[0].event_id == fs[-1].event_id and d[0].finding_type == "auth_anomaly"
    ev = d[0].evidence
    assert ev["observed"]["failed_login_count"] == 12 and ev["observed"]["duration_s"] == 22.0
    assert ev["event_ids"] == [e.event_id for e in fs] and ev["mitre_reference"]["technique_id"] == "T1110"
    assert only(run(failures(9)), "R-AUTH-001") == []                       # boundary: 9 < 10
    assert len(only(run(failures(10)), "R-AUTH-001")) == 1                  # boundary: exactly 10


def test_burst_confidence_increases_with_volume_and_is_capped():
    low = only(run(failures(10)), "R-AUTH-001")[0].confidence
    high = only(run(failures(200, step=0.1)), "R-AUTH-001")[0].confidence
    assert low == 0.75 and high == 0.95


def test_runs_split_by_gap_and_sources_not_merged():
    two = failures(10, 0) + failures(10, 500)                                # >30 s gap -> two runs
    assert len(only(run(two), "R-AUTH-001")) == 2
    split = failures(6, 0, ip="203.0.113.1") + failures(6, 1, ip="203.0.113.2")   # 12 total but 6 per source
    assert only(run(split), "R-AUTH-001") == []
    slow = failures(10, 0, step=40)                                          # each gap 40 s > run_gap -> never a run of 10
    assert only(run(slow), "R-AUTH-001") == []


def test_multi_account_failures():
    many = failures(12, users=["a", "b", "c", "d", "e", "f"])
    assert len(only(run(many), "R-AUTH-002")) == 1
    assert only(run(failures(12, users=["a"])), "R-AUTH-002") == []          # one account hammered != spraying
    assert only(run(failures(12, users=["a", "b", "c", "d"])), "R-AUTH-002") == []   # 4 < 5 distinct


def test_success_after_burst_with_and_without_account_match():
    burst = failures(12, users=["victim", "x"])
    ok = mk("login_success", 11 + 16, uid="victim", ep="/api/login", status=200, source="auth", method="POST")
    d = only(run(burst + [ok]), "R-AUTH-003")
    assert len(d) == 1 and d[0].event_id == ok.event_id and d[0].confidence == 0.9
    assert d[0].evidence["observed"]["account_was_targeted_in_burst"] is True
    assert d[0].evidence["derived_metrics"]["seconds_after_burst"] == 16.0 and d[0].evidence["mitre_reference"]["technique_id"] == "T1078"
    other = mk("login_success", 11 + 16, uid="someone-else", ep="/api/login", status=200, source="auth")
    d2 = only(run(burst + [other]), "R-AUTH-003")
    assert d2[0].confidence == 0.8 and d2[0].evidence["observed"]["account_was_targeted_in_burst"] is False


def test_success_not_flagged_when_early_late_or_elsewhere():
    burst = failures(12, users=["victim"])
    before = mk("login_success", -5, uid="victim", source="auth")
    late = mk("login_success", 11 + 601, uid="victim", source="auth")
    elsewhere = mk("login_success", 11 + 5, uid="victim", ip="198.51.100.9", source="auth")
    assert only(run(burst + [before, late, elsewhere]), "R-AUTH-003") == []


def test_benign_mistyped_password_and_normal_login_not_flagged():
    evs = failures(4, step=8, ip="192.0.2.200", users=["u-2000"]) + [mk("login_success", 40, ip="192.0.2.200", uid="u-2000", source="auth")]
    assert run(evs) == []


# ------------------------------------------------------------------ behaviour
def test_request_rate_boundaries_and_window_evidence():
    fast = [mk("http_request", i * 0.3, sid="bot", ep=f"/p/{i}", status=200, source="app", method="GET") for i in range(31)]   # 31 in 9 s
    d = only(run(fast), "R-BEH-001")
    assert len(d) == 1 and d[0].evidence["observed"]["requests_in_peak_window"] >= 30
    exactly = [mk("http_request", i * (10 / 29), sid="b", ep=f"/p/{i}", status=200, source="app") for i in range(30)]   # 30 within 10 s
    assert len(only(run(exactly), "R-BEH-001")) == 1
    short = [mk("http_request", i * 0.3, sid="b", ep=f"/p/{i}", status=200, source="app") for i in range(29)]
    assert only(run(short), "R-BEH-001") == []
    slow = [mk("http_request", i * 1.0, sid="b", ep=f"/p/{i}", status=200, source="app") for i in range(60)]   # 11 per 10 s
    assert only(run(slow), "R-BEH-001") == []


def test_login_failures_do_not_count_as_page_requests():
    assert only(run(failures(50, step=0.1)), "R-BEH-001") == []


def test_automation_signals_one_vs_two():
    one = only(run([mk("page_view", 0, ua=HEADLESS, ep="/")]), "R-BEH-002")
    assert len(one) == 1 and one[0].confidence == 0.55 and one[0].evidence["observed"]["signals"] == ["automation_user_agent"]
    two = only(run([mk("page_view", 0, ua=HEADLESS, ep="/", attrs={"webdriver": True})]), "R-BEH-002")
    assert two[0].confidence == 0.75 and two[0].evidence["derived_metrics"]["independent_signal_count"] == 2
    assert only(run([mk("page_view", 0, ep="/", attrs={"webdriver": False})]), "R-BEH-002") == []
    assert only(run([mk("page_view", 0, ep="/")]), "R-BEH-002") == []
    assert one[0].evidence["limitations"]


def test_non_human_navigation():
    pvs = [mk("page_view", i * 1.0, ep=f"/p{i}", attrs={"page_seq": i}) for i in range(6)]
    assert len(only(run(pvs), "R-BEH-003")) == 1
    with_inter = pvs + [mk("interaction", 2.5, attrs={"clicks": 1})]
    assert only(run(with_inter), "R-BEH-003") == []
    zero_inter = pvs + [mk("interaction", 2.5, attrs={"clicks": 0, "scroll_events": 0})]
    assert len(only(run(zero_inter), "R-BEH-003")) == 1                      # interaction event with all-zero counts is not human activity
    assert only(run(pvs[:4]), "R-BEH-003") == []                             # too few pages
    slow = [mk("page_view", i * 10.0, ep=f"/p{i}") for i in range(6)]
    assert only(run(slow), "R-BEH-003") == []                                # reading pace


def test_recon_path_probing():
    paths = ["/admin", "/robots.txt", "/api/docs"]
    d = only(run([mk("page_view", i, ep=p) for i, p in enumerate(paths)]), "R-BEH-004")
    assert len(d) == 1 and d[0].evidence["observed"]["probe_paths_requested"] == sorted(paths)
    assert only(run([mk("page_view", i, ep=p) for i, p in enumerate(paths[:2])]), "R-BEH-004") == []
    legit = [mk("sensitive_endpoint_access", i * 60, uid="admin-01", ep="/api/admin/dashboard", status=200, source="api") for i in range(4)]
    assert run(legit) == []                                                  # legitimate admin: sensitive access alone is not suspicious


# ------------------------------------------------------------------ attack indicators
ATTACKS = [
    ("R-ATK-001", "/products?id=1' OR '1'='1"), ("R-ATK-001", "/p?id=1 UNION SELECT NULL,NULL--"),
    ("R-ATK-001", "/p?id=1; DROP TABLE users--"), ("R-ATK-001", "/p?q=%27%20or%201%3D1"), ("R-ATK-001", "/p?q=1%2527%2520or%25201%253D1"),
    ("R-ATK-002", "/search?q=<script>alert(1)</script>"), ("R-ATK-002", '/search?q="><img src=x onerror=alert(1)>'),
    ("R-ATK-002", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("R-ATK-003", "/download?file=../../etc/passwd"), ("R-ATK-003", "/download?file=..%2F..%2Fwindows%2Fwin.ini"),
    ("R-ATK-004", "/fetch?url=http://169.254.169.254/latest/meta-data/"), ("R-ATK-004", "/fetch?url=http%3A%2F%2F10.0.0.5%2Fadmin"),
    ("R-ATK-004", "/fetch?u=file:///etc/passwd"),
]
BENIGN = ["/products/12", "/blog/9", "/search?q=black+or+white", "/search?q=select+a+color", "/api/reports/search?q=quarterly+sales",
          "/products?id=1", "/fetch?url=https://example.com/page", "/search?q=it's+a+great+day", "/cart?promo=SAVE-10--now",
          "/contact?name=O'Brien", "/about", "/api/orders", "/cart"]


@pytest.mark.parametrize("rule_id,endpoint", ATTACKS)
def test_attack_patterns_detected(rule_id, endpoint):
    d = only(run([mk("http_request", ep=endpoint, source="app", method="GET")]), rule_id)
    assert len(d) >= 1, endpoint
    ev = d[0].evidence
    assert ev["observed"]["matched_signals"] and ev["mitre_reference"]["technique_id"] == "T1190"
    assert "does not show the attempt succeeded" in ev["interpretation"]["text"]
    assert "request bodies and headers are not inspected" in " ".join(ev["limitations"]).lower()


@pytest.mark.parametrize("endpoint", BENIGN)
def test_benign_requests_not_flagged(endpoint):
    assert run([mk("http_request", ep=endpoint, source="app", method="GET")]) == []


def test_ssrf_only_checks_query_string():
    assert only(run([mk("http_request", ep="/http://169.254.169.254/x", source="app")]), "R-ATK-004") == []


def test_multi_vector_probing_and_window():
    probes = ["/p?id=1' OR '1'='1", "/s?q=<script>alert(1)</script>", "/d?f=../../etc/passwd"]
    evs = [mk("http_request", i * 5, ep=p, source="app", sid=None) for i, p in enumerate(probes)]
    d = only(run(evs), "R-ATK-005")
    assert len(d) == 1 and d[0].evidence["derived_metrics"]["distinct_categories"] == 3 and d[0].event_id == evs[-1].event_id
    assert only(run(evs[:2]), "R-ATK-005") == []                              # 2 categories < 3
    spread = [mk("http_request", i * 400, ep=p, source="app", sid=None) for i, p in enumerate(probes)]   # 800 s > 600 s window
    assert only(run(spread), "R-ATK-005") == []
    four = probes + ["/f?url=http://169.254.169.254/x"]
    evs4 = [mk("http_request", i * 5, ep=p, source="app", sid=None) for i, p in enumerate(four)]
    d4 = only(run(evs4), "R-ATK-005")
    assert len(d4) == 1 and d4[0].evidence["derived_metrics"]["distinct_categories"] == 4      # widest window, not first to qualify
    assert d4[0].event_id == evs4[-1].event_id and len(d4[0].evidence["event_ids"]) == 4
    same_cat = [mk("http_request", i, ep=f"/p?id=1' OR '{i}'='{i}", source="app") for i in range(5)]
    assert only(run(same_cat), "R-ATK-005") == []                             # many requests, one category


def test_waf_alert_recorded_as_reported_not_verified():
    w = mk("waf_alert", ep="/api/x", status=403, source="waf", attrs={"rule_name": "sql_injection_pattern", "mode": "detect_only"})
    d = run([w])
    assert rules_of(d) == ["R-WAF-001"] and d[0].finding_type == "waf_signal"
    assert d[0].evidence["observed"]["waf_rule_name"] == "sql_injection_pattern"
    assert "not verified" in d[0].evidence["interpretation"]["text"]


# ------------------------------------------------------------------ cross-cutting
def test_disabled_rule_and_custom_threshold():
    cfg = defaults()
    cfg.data["rules"]["R-AUTH-001"]["enabled"] = False
    assert only(run(failures(12), cfg), "R-AUTH-001") == []
    cfg2 = defaults()
    cfg2.data["rules"]["R-AUTH-001"]["min_failures"] = 3
    assert len(only(run(failures(3), cfg2), "R-AUTH-001")) == 1
    cfg3 = defaults()
    cfg3.data["rules"]["R-ATK-001"]["enabled"] = False
    assert only(run([mk("http_request", ep="/p?id=1 UNION SELECT 1", source="app")], cfg3), "R-ATK-001") == []


def test_every_finding_is_well_formed_and_traceable():
    events = (failures(12, users=list("abcdef")) + [mk("login_success", 30, uid="a", source="auth", ep="/api/login")]
              + [mk("http_request", 40, ep="/p?id=1 UNION SELECT 1", source="app", ua=HEADLESS)]
              + [mk("waf_alert", 41, ep="/api/x", source="waf", attrs={"rule_name": "r"})])
    ids = {e.event_id for e in events}
    drafts = run(events)
    assert len(drafts) >= 5
    for d in drafts:
        assert d.rule_id in RULES and d.event_id in ids and 0 <= d.confidence <= 1
        ev = d.evidence
        for key in ("rule_id", "observed", "derived_metrics", "interpretation", "event_ids", "limitations", "thresholds", "config_version"):
            assert key in ev, (d.rule_id, key)
        assert ev["interpretation"]["basis"] == "rule_template" and ev["limitations"]
        assert set(ev["event_ids"]) <= ids and d.event_id in ev["event_ids"]      # anchor is always part of its own evidence
        assert "enabled" not in ev["thresholds"]


def test_evaluation_is_deterministic_and_input_order_independent():
    events = failures(12, users=list("abcdef")) + [mk("http_request", 40, ep="/s?q=<script>", source="app")]
    a, b = run(events), run(list(reversed(events)))
    assert [(d.rule_id, d.event_id, d.confidence, d.evidence) for d in a] == [(d.rule_id, d.event_id, d.confidence, d.evidence) for d in b]


def test_evidence_id_list_is_capped():
    d = only(run(failures(600, step=0.01)), "R-AUTH-001")[0]
    assert len(d.evidence["event_ids"]) == 500 and d.evidence["event_ids_truncated"] is True
    assert d.evidence["observed"]["failed_login_count"] == 600
