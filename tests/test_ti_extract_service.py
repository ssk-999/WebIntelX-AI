"""Indicator extraction + enrichment service (PRD section 16, NFR Reliability, privacy gating)."""
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from app.config import get_settings
from app.threat_intel import providers as P
from app.threat_intel import service as S
from app.threat_intel.base import (
    ERROR, EVIDENCE_FOUND, IND_CVE, IND_DOMAIN, IND_IP, IND_TECHNIQUE, NOT_APPLICABLE, NOT_CONFIGURED, NO_EVIDENCE, TIMEOUT, Indicator, TIResult,
)
from app.threat_intel.config import defaults
from app.threat_intel.extract import extract_indicators
from tests.helpers import mk
from tests.ti_helpers import NVD_CVE, mock_client, otx_body


@pytest.fixture(autouse=True)
def _reset():
    P.nvd_limiter.reset()
    S.clear_cache()
    yield
    S.clear_cache()


def inc(ips=("8.8.8.8",)):
    return SimpleNamespace(incident_id="inc_t", details={"entities": {"source_ips": list(ips)}})


def finding(fid, tid=None):
    ev = {"mitre_reference": {"technique_id": tid, "name": "n"}} if tid else {"mitre_reference": None}
    return SimpleNamespace(finding_id=fid, evidence=ev)


def cfg_with(**over):
    c = defaults()
    for path, v in over.items():
        node = c.data
        *parents, leaf = path.split("__")
        for p in parents:
            node = node[p]
        node[leaf] = v
    return c


# ------------------------------------------------------------------------------------------ extract
def test_extracts_ips_cves_techniques_with_traceable_context():
    evs = [mk("http_request", 1, ep="/a?q=CVE-2021-44228", source="app", method="GET", status=200),
           mk("http_request", 2, ep="/b/cve-2021-44228", source="app", method="GET", status=200),
           mk("http_request", 3, ep="/c?x=CVE-2017-5638", source="app", method="GET", status=200),
           mk("http_request", 4, ep="/plain", source="app", method="GET", status=200)]
    got, dropped = extract_indicators(inc(("8.8.8.8", "1.1.1.1", "8.8.8.8")), evs, [finding("f1", "t1110"), finding("f2", "T1110"), finding("f3"), finding("f4", "T1190")],
                                      site_domain="s.example.com", cfg=defaults())
    by = {(i.type, i.value): i for i in got}
    assert [i.value for i in got if i.type == IND_IP] == ["1.1.1.1", "8.8.8.8"]                    # de-duplicated, sorted
    assert set(v for t, v in by if t == IND_CVE) == {"CVE-2021-44228", "CVE-2017-5638"}              # case-normalised
    assert by[(IND_CVE, "CVE-2021-44228")].context["event_ids"] == [evs[0].event_id, evs[1].event_id]
    assert set(v for t, v in by if t == IND_TECHNIQUE) == {"T1110", "T1190"}
    assert by[(IND_TECHNIQUE, "T1110")].context["finding_ids"] == ["f1", "f2"] and dropped == {}


def test_no_cve_or_technique_signal_means_none_extracted():
    got, _ = extract_indicators(inc(()), [mk("http_request", 1, ep="/plain", source="app", method="GET", status=200)], [finding("f")], site_domain="s.example.com", cfg=defaults())
    assert got == []


def test_cve_lookalikes_are_not_extracted():
    evs = [mk("http_request", 1, ep="/x?a=CVE-21-1&b=CVE-2021-12&c=XCVE-2021-1234567890", source="app", method="GET", status=200)]
    got, _ = extract_indicators(inc(()), evs, [], site_domain="s.example.com", cfg=defaults())
    assert [i for i in got if i.type == IND_CVE] == []


def test_domains_off_by_default_then_on_excluding_own_site():
    evs = [mk("page_view", 1, attrs={"referrer_host": "evil.example.net"}), mk("page_view", 2, attrs={"referrer_host": "shop.example.com"}),
           mk("page_view", 3, attrs={"referrer_host": "www.shop.example.com"}), mk("page_view", 4, attrs={"referrer_host": "localhost"}),
           mk("page_view", 5, attrs={"referrer_host": "10.0.0.1"})]
    off, _ = extract_indicators(inc(()), evs, [], site_domain="shop.example.com", cfg=defaults())
    assert [i for i in off if i.type == IND_DOMAIN] == []
    on, _ = extract_indicators(inc(()), evs, [], site_domain="shop.example.com", cfg=cfg_with(indicators__domains__enabled=True))
    assert [i.value for i in on if i.type == IND_DOMAIN] == ["evil.example.net"]


def test_cap_per_type_is_applied_and_reported():
    ips = [f"8.8.8.{i}" for i in range(1, 8)]
    got, dropped = extract_indicators(inc(ips), [], [], site_domain="x.com", cfg=cfg_with(indicators__max_per_incident=3))
    assert len([i for i in got if i.type == IND_IP]) == 3 and dropped == {IND_IP: 4}


def test_disabled_indicator_kinds_are_skipped():
    evs = [mk("http_request", 1, ep="/a?q=CVE-2021-44228", source="app", method="GET", status=200)]
    got, _ = extract_indicators(inc(), evs, [], site_domain="x.com", cfg=cfg_with(indicators__ips__enabled=False, indicators__cves__enabled=False))
    assert got == []


# ------------------------------------------------------------------------------------------- service
def look(ind, ps, cfg=None, handler=None, started=None):
    import time
    with mock_client(handler or (lambda r: pytest.fail("network call not expected"))) as c:
        return S._lookup(ind, ps, cfg or defaults(), c, time.monotonic() if started is None else started)


def otx_set(key="k"):
    return P.build_providers(replace(get_settings(), ti_provider="otx", ti_api_key=key), defaults())


@pytest.mark.parametrize("ip", ["203.0.113.77", "198.51.100.23", "192.0.2.1", "10.0.0.5", "127.0.0.1", "2001:db8::1",
                                "203.0.113.0/24", "a1b2c3d4e5f6", "not-an-ip", ""])
def test_non_public_or_masked_ips_are_never_sent_to_a_real_provider(ip):
    r = look(Indicator(IND_IP, ip), otx_set())
    assert r.status == NOT_APPLICABLE and "not sent to an external provider" in r.summary and "No threat-intelligence evidence was found" in r.summary


def test_query_non_public_relaxes_only_for_valid_single_ips():
    cfg = cfg_with(indicators__ips__query_non_public=True)
    called = []
    r = look(Indicator(IND_IP, "203.0.113.77"), otx_set(), cfg, lambda req: (called.append(1), httpx.Response(200, json=otx_body(1)))[1])
    assert r.status == EVIDENCE_FOUND and called
    masked = look(Indicator(IND_IP, "203.0.113.0/24"), otx_set(), cfg)         # a masked value is still never sent
    assert masked.status == NOT_APPLICABLE


def test_public_ip_is_queried():
    r = look(Indicator(IND_IP, "8.8.8.8"), otx_set(), handler=lambda req: httpx.Response(200, json=otx_body(3)))
    assert r.status == EVIDENCE_FOUND and r.data["pulse_count"] == 3


@pytest.mark.parametrize("provider,key,why", [("", "", "TI_PROVIDER"), ("otx", "", "API key"), ("abuseipdb", "k", "unsupported")])
def test_unconfigured_reputation_provider_is_explicit_and_queries_nothing(provider, key, why):
    ps = P.build_providers(replace(get_settings(), ti_provider=provider, ti_api_key=key), defaults())
    r = look(Indicator(IND_IP, "8.8.8.8"), ps)
    assert r.status == NOT_CONFIGURED and why in r.summary and "No threat-intelligence evidence is available" in r.summary and r.provider == "none"


def test_synthetic_provider_answers_documentation_ips_without_network():
    ps = P.build_providers(replace(get_settings(), ti_provider="synthetic_demo"), defaults())
    r = look(Indicator(IND_IP, "203.0.113.77"), ps)
    assert r.status == EVIDENCE_FOUND and r.synthetic


def test_unexpected_provider_exception_becomes_an_error_result():
    class Boom(P.MitreProvider):
        def lookup(self, ind, client):
            raise RuntimeError("secret detail")
    ps = P.ProviderSet(mitre=Boom())
    r = look(Indicator(IND_TECHNIQUE, "T1110"), ps)
    assert r.status == ERROR and "secret detail" not in r.summary


def test_cache_reuses_real_answers_and_marks_them():
    calls = []

    def h(req):
        calls.append(1)
        return httpx.Response(200, json=otx_body(1))

    ps, ip = otx_set(), Indicator(IND_IP, "8.8.8.8")
    first, second = look(ip, ps, handler=h), look(ip, ps, handler=h)
    assert len(calls) == 1 and not first.cached and second.cached and second.status == EVIDENCE_FOUND


def test_failures_are_never_cached():
    calls = []

    def h(req):
        calls.append(1)
        return httpx.Response(500)

    ps, ip = otx_set(), Indicator(IND_IP, "8.8.8.8")
    look(ip, ps, handler=h)
    look(ip, ps, handler=h)
    assert len(calls) == 2


def test_cache_ttl_zero_disables_cache():
    calls = []
    ps, ip = otx_set(), Indicator(IND_IP, "8.8.8.8")
    for _ in range(2):
        look(ip, ps, cfg_with(cache_ttl_s=0), lambda r: (calls.append(1), httpx.Response(200, json=otx_body(0)))[1])
    assert len(calls) == 2


def test_time_budget_skips_remaining_network_lookups_but_not_local_ones():
    ps = otx_set()
    r = look(Indicator(IND_IP, "8.8.8.8"), ps, cfg_with(deadline_s=1), started=-1000.0)
    assert r.status == TIMEOUT and "time budget" in r.summary
    local = look(Indicator(IND_TECHNIQUE, "T1110"), ps, cfg_with(deadline_s=1), started=-1000.0)
    assert local.status == EVIDENCE_FOUND


def test_one_provider_failing_does_not_stop_the_others():
    ps = otx_set()

    def h(req):
        if "alienvault" in str(req.url):
            return httpx.Response(500)
        return httpx.Response(200, json=NVD_CVE)

    import time
    with mock_client(h) as c:
        res = [S._lookup(i, ps, defaults(), c, time.monotonic()) for i in
               (Indicator(IND_IP, "8.8.8.8"), Indicator(IND_CVE, "CVE-2021-44228"), Indicator(IND_TECHNIQUE, "T1190"))]
    assert [r.status for r in res] == [ERROR, EVIDENCE_FOUND, EVIDENCE_FOUND]
    rep = S.build_report(res, ps, {}, "2026-10-03T00:00:00+00:00", 3)
    assert rep["status"] == "partial" and rep["counts"] == {"error": 1, "evidence_found": 2}


def test_report_status_and_synthetic_flag_and_dropped_notes():
    ps = P.build_providers(replace(get_settings(), ti_provider="synthetic_demo"), defaults())
    assert S.build_report([], ps, {}, "t", 0)["status"] == "no_indicators"
    r = TIResult(IND_IP, "1.2.3.4", "synthetic_demo", EVIDENCE_FOUND, "s", synthetic=True)
    rep = S.build_report([r], ps, {IND_IP: 2}, "t", 3)
    assert rep["status"] == "ok" and rep["contains_synthetic"] is True and any("2 ip indicator(s)" in n for n in rep["notes"])
    assert any("not proof of an attack" in d for d in rep["disclaimers"])
