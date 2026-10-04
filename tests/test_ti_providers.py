"""Provider behaviour against mocked HTTP (PRD section 16: show source/status, never invent, No-Evidence Rule)."""
import httpx
import pytest

from app.threat_intel import providers as P
from app.threat_intel.base import (
    ABSENCE_NOTE, ERROR, EVIDENCE_FOUND, IND_CVE, IND_DOMAIN, IND_IP, IND_TECHNIQUE, NO_EVIDENCE, RATE_LIMITED, TIMEOUT, Indicator,
)
from tests.ti_helpers import NVD_CVE, mock_client, otx_body

IP = Indicator(IND_IP, "8.8.8.8")


@pytest.fixture(autouse=True)
def _reset():
    P.nvd_limiter.reset()


def run(provider, ind, handler):
    with mock_client(handler) as c:
        return provider.lookup(ind, c)


# ----------------------------------------------------------------------------------------------- OTX
def test_otx_found_sends_key_header_and_uses_ipv4_endpoint():
    seen = {}

    def h(req):
        seen["url"], seen["key"] = str(req.url), req.headers.get("X-OTX-API-KEY")
        return httpx.Response(200, json=otx_body(2, country_name="Nowhere", asn="AS1 Example"))

    r = run(P.OTXProvider("sekret-key"), IP, h)
    assert seen["url"] == "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general" and seen["key"] == "sekret-key"
    assert r.status == EVIDENCE_FOUND and r.data["pulse_count"] == 2 and r.data["country"] == "Nowhere" and r.data["asn"] == "AS1 Example"
    assert r.source == seen["url"] and not r.synthetic and "not proof" in r.summary
    assert "sekret-key" not in str(r.to_dict())            # credentials never appear in results


def test_otx_ipv6_and_domain_endpoints():
    urls = []

    def h(req):
        urls.append(str(req.url))
        return httpx.Response(200, json=otx_body(0))

    run(P.OTXProvider("k"), Indicator(IND_IP, "2606:4700::1111"), h)
    run(P.OTXProvider("k"), Indicator(IND_DOMAIN, "example.org"), h)
    assert urls[0] == "https://otx.alienvault.com/api/v1/indicators/IPv6/2606:4700::1111/general"
    assert urls[1] == "https://otx.alienvault.com/api/v1/indicators/domain/example.org/general"


def test_otx_zero_pulses_is_explicit_no_evidence_with_context_only():
    r = run(P.OTXProvider("k"), IP, lambda req: httpx.Response(200, json=otx_body(0, country_name="Nowhere")))
    assert r.status == NO_EVIDENCE and r.data == {"country": "Nowhere"}
    assert "No threat-intelligence evidence was found" in r.summary and ABSENCE_NOTE in r.summary
    assert r.to_dict()["evidence_status"] == "no_evidence"
    assert "not a claim that the indicator is safe" in ABSENCE_NOTE and "not a claim that it is malicious" in ABSENCE_NOTE


def test_otx_404_is_no_evidence_not_error():
    r = run(P.OTXProvider("k"), IP, lambda req: httpx.Response(404, json={"detail": "x"}))
    assert r.status == NO_EVIDENCE and "No threat-intelligence evidence was found" in r.summary


@pytest.mark.parametrize("code,status", [(429, RATE_LIMITED), (401, ERROR), (403, ERROR), (500, ERROR), (503, ERROR)])
def test_otx_http_failures_are_reported_with_status(code, status):
    r = run(P.OTXProvider("k"), IP, lambda req: httpx.Response(code))
    assert r.status == status and f"{code}" in r.summary and "no threat-intelligence evidence is available" in r.summary.lower()


def test_otx_timeout_and_network_error_never_raise_and_hide_exception_text():
    def boom_timeout(req):
        raise httpx.ReadTimeout("secret-url-in-message", request=req)

    def boom_net(req):
        raise httpx.ConnectError("secret-url-in-message", request=req)

    t = run(P.OTXProvider("k"), IP, boom_timeout)
    n = run(P.OTXProvider("k"), IP, boom_net)
    assert t.status == TIMEOUT and n.status == ERROR
    assert "secret-url-in-message" not in t.summary + n.summary


@pytest.mark.parametrize("content", [b"not json", b"[1,2]", b""])
def test_otx_unreadable_body_is_error(content):
    r = run(P.OTXProvider("k"), IP, lambda req: httpx.Response(200, content=content))
    assert r.status == ERROR


def test_otx_sanitises_untrusted_third_party_text():
    body = otx_body(1)
    body["pulse_info"]["pulses"] = [{"name": "<script>x</script>\x00\x1b[31m" + "A" * 500}]
    r = run(P.OTXProvider("k"), IP, lambda req: httpx.Response(200, json=body))
    name = r.data["example_pulse_names"][0]
    assert len(name) <= 80 and "\x00" not in name and "\x1b" not in name


def test_otx_malformed_fields_do_not_crash():
    for body in ({"pulse_info": "oops"}, {"pulse_info": {"count": "5"}}, {"pulse_info": {"count": True}}, {"pulse_info": {"count": 2, "pulses": "x"}}):
        r = run(P.OTXProvider("k"), IP, lambda req, b=body: httpx.Response(200, json=b))
        assert r.status in (NO_EVIDENCE, EVIDENCE_FOUND)


# ----------------------------------------------------------------------------------------------- NVD
CVE = Indicator(IND_CVE, "CVE-2021-44228")


def test_nvd_found_parses_only_returned_fields():
    seen = {}

    def h(req):
        seen["url"], seen["key"] = str(req.url), req.headers.get("apiKey")
        return httpx.Response(200, json=NVD_CVE)

    r = run(P.NVDProvider(), CVE, h)
    assert seen["url"] == "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" and seen["key"] is None
    assert r.status == EVIDENCE_FOUND and r.data["cvss"] == {"version": "3.1", "base_score": 10.0, "severity": "CRITICAL"}
    assert r.data["description"].startswith("Remote code execution") and "\x00" not in r.data["description"]
    assert r.data["weaknesses"] == ["CWE-502"] and "does not show that this website is affected" in r.limitations[0]


def test_nvd_sends_api_key_only_when_configured_and_never_returns_it():
    seen = {}

    def h(req):
        seen["key"] = req.headers.get("apiKey")
        return httpx.Response(200, json=NVD_CVE)

    r = run(P.NVDProvider("nvd-secret"), CVE, h)
    assert seen["key"] == "nvd-secret" and "nvd-secret" not in str(r.to_dict())


def test_nvd_empty_result_is_explicit_no_evidence():
    r = run(P.NVDProvider(), CVE, lambda req: httpx.Response(200, json={"vulnerabilities": []}))
    assert r.status == NO_EVIDENCE and "No threat-intelligence evidence was found" in r.summary and ABSENCE_NOTE in r.summary


def test_nvd_mismatched_cve_in_response_is_not_trusted():
    body = {"vulnerabilities": [{"cve": {"id": "CVE-1999-0001", "descriptions": []}}]}
    r = run(P.NVDProvider(), CVE, lambda req: httpx.Response(200, json=body))
    assert r.status == NO_EVIDENCE


def test_nvd_missing_metrics_gives_no_invented_severity():
    body = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "descriptions": []}}]}
    r = run(P.NVDProvider(), CVE, lambda req: httpx.Response(200, json=body))
    assert r.status == EVIDENCE_FOUND and "cvss" not in r.data and "CVSS" not in r.summary


@pytest.mark.parametrize("code,status", [(429, RATE_LIMITED), (403, ERROR), (500, ERROR)])
def test_nvd_http_failures(code, status):
    assert run(P.NVDProvider(), CVE, lambda req: httpx.Response(code)).status == status


def test_nvd_local_limiter_skips_the_request_when_budget_is_spent():
    calls = []

    def h(req):
        calls.append(1)
        return httpx.Response(200, json=NVD_CVE)

    prov = P.NVDProvider(limit_without_key=2)
    statuses = [run(prov, CVE, h).status for _ in range(4)]
    assert statuses == [EVIDENCE_FOUND, EVIDENCE_FOUND, RATE_LIMITED, RATE_LIMITED] and len(calls) == 2


def test_nvd_key_raises_the_local_budget():
    prov = P.NVDProvider("k", limit_without_key=1, limit_with_key=3)
    assert [run(prov, CVE, lambda r: httpx.Response(200, json=NVD_CVE)).status for _ in range(3)] == [EVIDENCE_FOUND] * 3


def test_nvd_timeout():
    def boom(req):
        raise httpx.ConnectTimeout("x", request=req)
    assert run(P.NVDProvider(), CVE, boom).status == TIMEOUT


# --------------------------------------------------------------------------------------------- MITRE
def test_mitre_known_technique_is_context_with_disclaimer():
    r = run(P.MitreProvider(), Indicator(IND_TECHNIQUE, "T1110"), lambda req: pytest.fail("no network expected"))
    assert r.status == EVIDENCE_FOUND and r.data["name"] == "Brute Force" and r.data["tactics"] == ["Credential Access"]
    assert r.data["url"] == "https://attack.mitre.org/techniques/T1110/" and "not proof" in r.summary


def test_mitre_unknown_technique_is_no_evidence_not_invented():
    r = run(P.MitreProvider(), Indicator(IND_TECHNIQUE, "T9999"), lambda req: pytest.fail("no network expected"))
    assert r.status == NO_EVIDENCE and "name" not in r.data


def test_every_rule_technique_has_a_local_mapping_matching_the_rule_name():
    from app.detection.rules import RULES
    used = {m.mitre for m in RULES.values() if m.mitre}
    assert used, "rules should reference techniques"
    for tid, name in used:
        assert P.ATTACK_SUBSET[tid]["name"] == name


# ------------------------------------------------------------------------------------------ synthetic
def test_synthetic_results_are_loudly_labelled_and_flagged():
    r = run(P.SyntheticDemoProvider(), Indicator(IND_IP, "203.0.113.77"), lambda req: pytest.fail("no network expected"))
    assert r.status == EVIDENCE_FOUND and r.synthetic is True
    assert r.summary.startswith("SYNTHETIC DEMO DATA (not real threat intelligence)") and r.to_dict()["synthetic"] is True
    assert all(k.startswith("simulated_") for k in r.data)


def test_synthetic_unknown_ip_is_no_evidence_still_labelled():
    r = run(P.SyntheticDemoProvider(), Indicator(IND_IP, "192.0.2.5"), lambda req: pytest.fail("no network expected"))
    assert r.status == NO_EVIDENCE and r.synthetic and "SYNTHETIC" in r.summary


def test_synthetic_missing_file_degrades_to_no_evidence(tmp_path):
    r = run(P.SyntheticDemoProvider(tmp_path / "missing.json"), Indicator(IND_IP, "203.0.113.77"), lambda req: pytest.fail("x"))
    assert r.status == NO_EVIDENCE


def test_synthetic_fixture_covers_exactly_the_demo_attacker_ips():
    from app.demo.generator import ATTACKER_IP, BOT_IP, SQLI_IP
    assert set(P.SyntheticDemoProvider()._records()) == {ATTACKER_IP, SQLI_IP, BOT_IP}


# ------------------------------------------------------------------------------------------- registry
def _settings(provider="", key=""):
    from dataclasses import replace
    from app.config import get_settings
    return replace(get_settings(), ti_provider=provider, ti_api_key=key)


def test_registry_provider_selection_and_status():
    from app.threat_intel.config import defaults
    cfg = defaults()
    assert P.build_providers(_settings(), cfg).reputation_status == "not_configured"
    assert P.build_providers(_settings("otx"), cfg).reputation_status == "missing_api_key"
    ps = P.build_providers(_settings("OTX", "k"), cfg)
    assert ps.reputation_status == "ok" and ps.reputation.name == "otx"
    assert P.build_providers(_settings("abuseipdb", "k"), cfg).reputation_status == "unknown_provider"
    syn = P.build_providers(_settings("synthetic_demo"), cfg)
    assert syn.reputation.synthetic and any("SYNTHETIC" in n for n in syn.notes)
    assert ps.cve.name == "nvd_cve" and ps.mitre.name == "mitre_attack"


def test_registry_public_status_has_no_secrets():
    from app.threat_intel.config import defaults
    pub = str(P.build_providers(_settings("otx", "super-secret"), defaults(), "nvd-secret").public())
    assert "super-secret" not in pub and "nvd-secret" not in pub


def test_registry_respects_disabled_providers():
    from app.threat_intel.config import defaults
    cfg = defaults()
    cfg.data["nvd"]["enabled"] = False
    cfg.data["mitre"]["enabled"] = False
    ps = P.build_providers(_settings(), cfg)
    assert ps.cve is None and ps.mitre is None
