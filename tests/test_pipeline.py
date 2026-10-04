import pytest

from app.config import get_settings
from app.database.models import Website
from app.pipeline.pipeline import EventRejected, process_event


def _site(retain=False):
    return Website(website_id="web_1", account_id="acc_1", domain="x.com", retain_raw_data=retain)


def test_valid_event_normalised_and_masked():
    ev = process_event(
        {"event_type": "login_failure", "source": "auth", "method": "post", "endpoint": "api/login?password=pw&u=1",
         "source_ip": "203.0.113.9", "user_id": "bob@corp.com", "status_code": 401,
         "attributes": {"password": "pw", "note": "mail bob@corp.com"}},
        _site(), get_settings(),
    )
    assert ev.method == "POST" and ev.endpoint.startswith("/api/login")
    assert ev.endpoint == "/api/login?password=[REDACTED]&u=1"
    assert "@" not in ev.user_id
    assert ev.processed_data["attributes"]["password"] == "[REDACTED]"
    assert "bob@corp.com" not in str(ev.processed_data)
    assert ev.raw_data is None and ev.timestamp.tzinfo is not None


def test_raw_retention_still_strips_secrets():
    ev = process_event({"event_type": "page_view", "attributes": {"password": "pw", "a": 1}}, _site(True), get_settings())
    assert ev.raw_data["attributes"]["password"] == "[REDACTED]" and ev.raw_data["attributes"]["a"] == 1


@pytest.mark.parametrize("bad", [
    {"event_type": "nope"},
    {"event_type": "page_view", "source_ip": "999.1.1.1"},
    {"event_type": "page_view", "status_code": 42},
    {"event_type": "page_view", "unknown_field": 1},
    {"event_type": "page_view", "timestamp": "2999-01-01T00:00:00Z"},
    {"event_type": "page_view", "attributes": {"x": "a" * 9000}},
])
def test_invalid_events_rejected(bad):
    with pytest.raises(EventRejected):
        process_event(bad, _site(), get_settings())


def test_sdk_ip_fallback_only_for_sdk():
    s = get_settings()
    assert process_event({"event_type": "page_view"}, _site(), s, fallback_ip="198.51.100.4").source_ip == "198.51.100.4"
    assert process_event({"event_type": "waf_alert", "source": "waf"}, _site(), s, fallback_ip="198.51.100.4").source_ip is None
