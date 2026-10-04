from app.pipeline.sessionization import peak_in_window, session_key, sessionize
from tests.helpers import mk


def test_peak_in_window():
    assert peak_in_window([], 10) == (0, -1)
    assert peak_in_window([0, 1, 2, 30, 31], 10) == (3, 2)
    assert peak_in_window([0, 10, 20], 10)[0] == 2            # boundary is inclusive (<= window)
    assert peak_in_window([0, 11, 22], 10)[0] == 1


def test_grouping_and_fallback_keys():
    evs = [mk("page_view", 0, sid="a"), mk("page_view", 5, sid="a"), mk("http_request", 1, sid=None, ip="198.51.100.1"),
           mk("waf_alert", 2, sid=None, ip=None, source="waf")]
    out = sessionize(evs)
    assert set(out) == {"a", "ip:198.51.100.1", "unknown"}
    assert out["a"].inferred is False and out["ip:198.51.100.1"].inferred is True
    assert session_key(evs[3]) == ("unknown", True)


def test_session_metrics():
    evs = [mk("page_view", i * 2, sid="s", attrs={"webdriver": True}, ua="Scrapy/2.0") for i in range(5)]
    evs += [mk("interaction", 3, sid="s", attrs={"clicks": 2, "mouse_moves": 8}),
            mk("login_failure", 4, sid="s", uid="u1", source="auth"), mk("login_failure", 5, sid="s", uid="u2", source="auth"),
            mk("sensitive_endpoint_access", 6, sid="s", ep="/api/admin/x", status=200, source="api"),
            mk("http_request", 7, sid="s", ep="/x", status=404, source="app")]
    s = sessionize(evs)["s"]
    assert s.event_count == 10 and s.page_views == 5 and s.interaction_events == 1 and s.interaction_total == 10
    assert s.login_failures == 2 and s.distinct_failed_users == 2 and s.sensitive_accesses == 1 and s.error_events == 1
    assert s.median_page_gap_s == 2.0 and s.webdriver_seen and s.ua_classes == ["automation_tool", "browser"]  # mixed UAs in one session are both reported
    assert s.duration_s == 8.0 and s.request_events == 7 and s.peak_requests_10s == 7
    assert s.to_dict()["first_seen"].startswith("2026-10-03") and "event_ids" not in s.to_dict()
    assert len(s.to_dict(include_event_ids=True)["event_ids"]) == 10


def test_single_event_session_has_no_rates():
    s = sessionize([mk("page_view", 0, sid="solo")])["solo"]
    assert s.duration_s == 0 and s.median_page_gap_s is None and s.requests_per_min is None
