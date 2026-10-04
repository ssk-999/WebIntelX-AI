"""Regression for a real M8 leak found while building M10: incident titles ("... from 203.0.113.77") and threat-intel summaries carried literal IPs to the LLM."""
from app.agents.evidence import IP_PLACEHOLDER, safe_text


def test_literal_ips_in_free_text_are_replaced():
    assert safe_text("Suspicious activity chain from 203.0.113.77: abnormal navigation", 200) == f"Suspicious activity chain from {IP_PLACEHOLDER}: abnormal navigation"
    assert "198.51.100.7" not in safe_text("Nothing was queried for 198.51.100.7 because no provider is configured", 200)
    assert "2001" not in safe_text("source 2001:db8::1 and 2001:0db8:0000:0000:0000:0000:0000:0001 seen", 200)


def test_non_ip_numbers_and_clock_times_are_untouched():
    assert safe_text("126 failed logins in 18 s at 10:31:02 and 10:31:18", 200) == "126 failed logins in 18 s at 10:31:02 and 10:31:18"
    assert safe_text("version 1.2.3 build 10.5 score 0.82", 200) == "version 1.2.3 build 10.5 score 0.82"
