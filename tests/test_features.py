from app.detection.config import defaults
from app.pipeline.features import classify_user_agent
from tests.helpers import BROWSER, HEADLESS, mk

CFG = defaults()


def test_ua_classification():
    assert classify_user_agent(HEADLESS, CFG) == "headless_browser"
    assert classify_user_agent("Scrapy/2.11.0 (+https://scrapy.org)", CFG) == "automation_tool"
    assert classify_user_agent("curl/8.1.2", CFG) == "automation_tool"
    assert classify_user_agent(BROWSER, CFG) == "browser"
    assert classify_user_agent("", CFG) == "empty" and classify_user_agent(None, CFG) == "empty"
    assert classify_user_agent("SomeAgent/1.0", CFG) == "other"


def test_stored_event_has_versioned_features():
    e = mk("http_request", ep="/api/reports/search?q=%27+OR+1%3D1--", status=500, ua=HEADLESS, method="GET", source="app")
    f = e.features
    assert f["v"] == 1 and f["path"] == "/api/reports/search" and f["path_depth"] == 3
    assert f["has_query"] and f["param_count"] == 1 and f["special_char_count"] >= 1
    assert f["is_request_event"] and f["is_error_status"] and f["status_class"] == "5xx"
    assert f["ua_class"] == "headless_browser" and f["hour_utc"] == 9


def test_sensitive_auth_and_defaults():
    assert mk("api_access", ep="/api/admin/dashboard").features["is_sensitive_endpoint"] is True
    assert mk("api_access", ep="/api/adminx").features["is_sensitive_endpoint"] is False      # prefix needs a path boundary
    assert mk("sensitive_endpoint_access", ep="/anything").features["is_sensitive_endpoint"] is True
    assert mk("login_failure", ep="/api/login", source="auth").features["is_auth_endpoint"] is True
    f = mk("session_created", ep=None, source="auth").features
    assert f["path"] is None and f["path_depth"] == 0 and f["has_query"] is False and f["status_class"] is None
    assert f["is_auth_event"] is True and f["is_request_event"] is False


def test_interaction_and_webdriver_features_are_type_safe():
    e = mk("interaction", attrs={"clicks": 2, "key_events": 3, "scroll_events": True, "mouse_moves": "many", "dwell_ms": 5})
    assert e.features["interaction_total"] == 5                  # bool and str values ignored, never trusted
    assert mk("page_view", attrs={"webdriver": True, "page_seq": 3, "load_ms": 120}).features["webdriver"] is True
    f = mk("page_view", attrs={"webdriver": "yes", "load_ms": -5}).features
    assert f["webdriver"] is None and f["load_ms"] == 0
    assert mk("page_view").features["interaction_total"] is None


def test_features_come_from_masked_data():
    e = mk("http_request", ep="/api/x?token=abc123secret&q=1", source="app")
    assert "abc123secret" not in str(e.features) and e.features["param_count"] == 2
