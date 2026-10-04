"""Threat-intelligence providers (PRD section 16, FR-13).

PRD does not specify which providers to use ("only providers available within acceptable free or low-cost
limits at implementation time"), so these implementation decisions were made and the endpoints verified from
public documentation on 2026-10-03 (live calls were NOT exercised from the build sandbox; tests use mocked HTTP):

  otx             AlienVault OTX, IPv4/IPv6 and domain "general" indicator endpoint, header X-OTX-API-KEY.
                  Needs a (free) OTX account key in TI_API_KEY. Selected with TI_PROVIDER=otx.
  nvd_cve         NVD CVE API 2.0 `?cveId=`. Works without a key (public limit 5 requests / 30 s); optional
                  NVD_API_KEY (header `apiKey`, 50 requests / 30 s). Used only when a valid CVE id is present.
  mitre_attack    Local ATT&CK context table (no network). Reference context, never proof.
  synthetic_demo  Clearly labelled SYNTHETIC records for the demo's documentation-range IPs
                  (TI_PROVIDER=synthetic_demo). PRD section 40 allows a "mock/synthetic fallback for demo".

AbuseIPDB is deliberately not implemented (project decision; the Provider interface makes adding it a new class).
Provider names, quotas and response shapes can change: they are isolated here so a change touches one class.
Nothing in this module logs or returns a credential.
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from app.config import Settings
from app.security import RateLimiter
from app.threat_intel.base import (
    ABSENCE_NOTE, ERROR, EVIDENCE_FOUND, IND_CVE, IND_DOMAIN, IND_IP, IND_TECHNIQUE, MITRE_NOTE, NO_EVIDENCE, RATE_LIMITED, TIMEOUT,
    Indicator, Provider, TIResult, clean_text, no_evidence_text, parse_ip,
)
from app.threat_intel.config import ThreatIntelConfig

log = logging.getLogger("webintelx.threat_intel")
SYNTHETIC_FILE = Path(__file__).resolve().parents[2] / "data" / "synthetic_threat_intel.json"
nvd_limiter = RateLimiter()   # per process; NVD's public limit is per client address


def failure_result(ind: Indicator, provider: str, source: str, exc: Exception) -> TIResult:
    """Map a transport exception to a result. The exception text is never exposed (it can contain URLs)."""
    if isinstance(exc, httpx.TimeoutException):
        return TIResult(ind.type, ind.value, provider, TIMEOUT, f"{provider} did not answer in time; no threat-intelligence evidence is available from it.", source=source)
    return TIResult(ind.type, ind.value, provider, ERROR, f"{provider} could not be reached ({type(exc).__name__}); no threat-intelligence evidence is available from it.", source=source)


def status_result(ind: Indicator, provider: str, source: str, code: int) -> TIResult | None:
    """Result for a non-200 HTTP status, or None when the status is 200."""
    if code == 200:
        return None
    if code == 429:
        return TIResult(ind.type, ind.value, provider, RATE_LIMITED, f"{provider} rate-limited the request (HTTP 429); no threat-intelligence evidence is available from it right now.", source=source)
    if code in (401, 403):
        return TIResult(ind.type, ind.value, provider, ERROR, f"{provider} refused the request (HTTP {code}); this can mean an invalid or missing credential or a rate limit. No threat-intelligence evidence is available from it.", source=source)
    return TIResult(ind.type, ind.value, provider, ERROR, f"{provider} returned HTTP {code}; no threat-intelligence evidence is available from it.", source=source)


# ------------------------------------------------------------------------------------------------ OTX
class OTXProvider(Provider):
    name = "otx"
    indicator_types = (IND_IP, IND_DOMAIN)
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, timeout_s: float = 8.0) -> None:
        self._key = api_key
        self.timeout_s = timeout_s

    def _url(self, ind: Indicator) -> str:
        if ind.type == IND_IP:
            ip = parse_ip(ind.value)
            kind = "IPv6" if ip is not None and ip.version == 6 else "IPv4"
            return f"{self.BASE}/indicators/{kind}/{quote(ind.value, safe=':')}/general"   # validated IPs hold only hex, '.' and ':'
        return f"{self.BASE}/indicators/domain/{quote(ind.value, safe='')}/general"

    def lookup(self, ind: Indicator, client: httpx.Client) -> TIResult:
        url = self._url(ind)
        try:
            resp = client.get(url, headers={"X-OTX-API-KEY": self._key}, timeout=self.timeout_s)
        except httpx.HTTPError as exc:
            return failure_result(ind, self.name, url, exc)
        if resp.status_code == 404:        # unknown to the provider = no evidence
            return TIResult(ind.type, ind.value, self.name, NO_EVIDENCE, no_evidence_text(ind.value, "AlienVault OTX"), source=url)
        bad = status_result(ind, self.name, url, resp.status_code)
        if bad:
            return bad
        try:
            body = resp.json()
            if not isinstance(body, dict):
                raise ValueError("unexpected body")
        except ValueError:
            return TIResult(ind.type, ind.value, self.name, ERROR, "AlienVault OTX returned an unreadable response; no threat-intelligence evidence is available from it.", source=url)

        info = body.get("pulse_info") if isinstance(body.get("pulse_info"), dict) else {}
        count = info.get("count") if isinstance(info.get("count"), int) and not isinstance(info.get("count"), bool) else 0
        context: dict[str, Any] = {}
        for src, dst in (("country_name", "country"), ("asn", "asn"), ("reputation", "reputation")):
            if body.get(src) not in (None, ""):
                context[dst] = clean_text(body[src], 80)
        limitations = ["OTX pulses are community-submitted collections; membership is context for an analyst, not proof of malicious activity."]
        if count > 0:
            pulses = info.get("pulses") if isinstance(info.get("pulses"), list) else []
            names = [clean_text(p["name"], 80) for p in pulses[:3] if isinstance(p, dict) and p.get("name")]
            data = {"pulse_count": count, "example_pulse_names": names, **context}
            return TIResult(ind.type, ind.value, self.name, EVIDENCE_FOUND,
                            f"{ind.value} appears in {count} AlienVault OTX community pulse(s). This is reported context, not proof of malicious activity.",
                            data=data, source=url, limitations=limitations)
        return TIResult(ind.type, ind.value, self.name, NO_EVIDENCE, no_evidence_text(ind.value, "AlienVault OTX"),
                        data=context, source=url, limitations=limitations)

    def public_status(self) -> dict[str, Any]:
        return {**super().public_status(), "configured": True}


# ------------------------------------------------------------------------------------------------ NVD
class NVDProvider(Provider):
    name = "nvd_cve"
    indicator_types = (IND_CVE,)
    requires_public_ip = False
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = "", timeout_s: float = 8.0, limit_without_key: int = 5, limit_with_key: int = 50) -> None:
        self._key = api_key
        self.timeout_s = timeout_s
        self._limit = limit_with_key if api_key else limit_without_key

    def lookup(self, ind: Indicator, client: httpx.Client) -> TIResult:
        source = f"{self.BASE}?cveId={quote(ind.value, safe='')}"
        if not nvd_limiter.allow("nvd", self._limit, window_s=30.0):
            return TIResult(ind.type, ind.value, self.name, RATE_LIMITED,
                            "The local NVD request budget (30-second window) is used up; the lookup was skipped, not sent. No threat-intelligence evidence is available from NVD right now.",
                            source=source)
        headers = {"apiKey": self._key} if self._key else {}
        try:
            resp = client.get(self.BASE, params={"cveId": ind.value}, headers=headers, timeout=self.timeout_s)
        except httpx.HTTPError as exc:
            return failure_result(ind, self.name, source, exc)
        bad = status_result(ind, self.name, source, resp.status_code)
        if bad:
            return bad
        try:
            body = resp.json()
            vulns = body.get("vulnerabilities")
            if not isinstance(vulns, list):
                raise ValueError("unexpected body")
        except (ValueError, AttributeError):
            return TIResult(ind.type, ind.value, self.name, ERROR, "NVD returned an unreadable response; no vulnerability evidence is available from it.", source=source)
        cve = next((v["cve"] for v in vulns if isinstance(v, dict) and isinstance(v.get("cve"), dict) and str(v["cve"].get("id", "")).upper() == ind.value), None)
        if cve is None:
            return TIResult(ind.type, ind.value, self.name, NO_EVIDENCE,
                            f"No threat-intelligence evidence was found for {ind.value} in NVD: no record exists (it may be unpublished or not a real identifier). {ABSENCE_NOTE}",
                            source=source)

        desc = next((d.get("value") for d in cve.get("descriptions", []) if isinstance(d, dict) and d.get("lang") == "en" and d.get("value")), None)
        data: dict[str, Any] = {"cve_id": ind.value}
        for k in ("published", "lastModified", "vulnStatus"):
            if cve.get(k):
                data[k] = clean_text(cve[k], 40)
        if desc:
            data["description"] = clean_text(desc, 300)
        metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
        for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            rows = metrics.get(key)
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                cd = rows[0].get("cvssData") if isinstance(rows[0].get("cvssData"), dict) else {}
                score = cd.get("baseScore")
                if isinstance(score, (int, float)) and not isinstance(score, bool):
                    sev = cd.get("baseSeverity") or rows[0].get("baseSeverity")
                    data["cvss"] = {"version": label, "base_score": score, **({"severity": clean_text(sev, 20)} if sev else {})}
                    break
        cwes = [clean_text(d.get("value"), 30) for w in cve.get("weaknesses", []) if isinstance(w, dict)
                for d in w.get("description", []) if isinstance(d, dict) and str(d.get("value", "")).startswith("CWE-")]
        if cwes:
            data["weaknesses"] = sorted(set(cwes))[:5]
        sev_txt = f" (CVSS {data['cvss']['version']} base score {data['cvss']['base_score']})" if "cvss" in data else ""
        return TIResult(ind.type, ind.value, self.name, EVIDENCE_FOUND,
                        f"{ind.value} is a published NVD record{sev_txt}.", data=data, source=source,
                        limitations=["A CVE identifier in a request shows the vulnerability exists and its published severity; it does not show that this website is affected or that exploitation succeeded."])

    def public_status(self) -> dict[str, Any]:
        return {**super().public_status(), "configured": True, "api_key_set": bool(self._key)}


# --------------------------------------------------------------------------------------------- MITRE
# Hand-maintained subset: only the techniques this platform's rules reference. Verify against attack.mitre.org.
ATTACK_SUBSET: dict[str, dict[str, Any]] = {
    "T1110": {"name": "Brute Force", "tactics": ["Credential Access"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["Initial Access"]},
}


class MitreProvider(Provider):
    name = "mitre_attack"
    indicator_types = (IND_TECHNIQUE,)
    requires_public_ip = False
    network = False

    def lookup(self, ind: Indicator, client: httpx.Client) -> TIResult:
        src = "local table (subset of MITRE ATT&CK enterprise techniques)"
        row = ATTACK_SUBSET.get(ind.value.upper())
        if row is None:
            return TIResult(ind.type, ind.value, self.name, NO_EVIDENCE,
                            f"{ind.value} is not in this platform's local ATT&CK subset, so no mapping context is shown. {MITRE_NOTE}", source=src)
        data = {"technique_id": ind.value.upper(), "name": row["name"], "tactics": row["tactics"],
                "url": f"https://attack.mitre.org/techniques/{ind.value.upper()}/"}
        return TIResult(ind.type, ind.value, self.name, EVIDENCE_FOUND,
                        f"{ind.value.upper()} {row['name']} ({', '.join(row['tactics'])}). {MITRE_NOTE}", data=data, source=src,
                        limitations=[MITRE_NOTE], context=dict(ind.context))


# -------------------------------------------------------------------------------------- synthetic demo
class SyntheticDemoProvider(Provider):
    """Clearly labelled fake records for the demo's documentation-range IPs (PRD section 40 mock fallback).
    Every result and summary says SYNTHETIC; consumers must treat `synthetic=True` as non-evidence."""

    name = "synthetic_demo"
    indicator_types = (IND_IP,)
    synthetic = True
    requires_public_ip = False
    network = False
    _lock = threading.Lock()

    def __init__(self, path: Path = SYNTHETIC_FILE) -> None:
        self._path = path

    def _records(self) -> dict[str, Any]:
        try:
            with self._lock:
                body = json.loads(self._path.read_text(encoding="utf-8"))
            ips = body.get("ips")
            return ips if isinstance(ips, dict) else {}
        except (OSError, ValueError):
            return {}

    def lookup(self, ind: Indicator, client: httpx.Client) -> TIResult:
        tag = "SYNTHETIC DEMO DATA (not real threat intelligence)"
        rec = self._records().get(ind.value)
        if not isinstance(rec, dict):
            return TIResult(ind.type, ind.value, self.name, NO_EVIDENCE, f"{tag}: no simulated record for {ind.value}. {no_evidence_text(ind.value, 'the synthetic demo provider')}",
                            source=str(self._path.name), synthetic=True)
        return TIResult(ind.type, ind.value, self.name, EVIDENCE_FOUND,
                        f"{tag}: {ind.value} has an invented record ({clean_text(rec.get('simulated_label', 'simulated'), 80)}). This describes no real host.",
                        data={k: (clean_text(v, 120) if isinstance(v, str) else v) for k, v in rec.items()}, source=str(self._path.name), synthetic=True,
                        limitations=["Invented demo record; it must not influence a real risk decision."])


# ------------------------------------------------------------------------------------------- registry
@dataclass
class ProviderSet:
    reputation: Provider | None = None
    cve: Provider | None = None
    mitre: Provider | None = None
    reputation_status: str = "not_configured"   # ok | not_configured | missing_api_key | unknown_provider
    notes: list[str] = field(default_factory=list)

    def for_type(self, indicator_type: str) -> Provider | None:
        return {IND_IP: self.reputation, IND_DOMAIN: self.reputation, IND_CVE: self.cve, IND_TECHNIQUE: self.mitre}.get(indicator_type)

    def public(self) -> dict[str, Any]:
        def one(p: Provider | None) -> dict[str, Any] | None:
            return p.public_status() if p else None
        return {"reputation": {"status": self.reputation_status, "provider": one(self.reputation)},
                "cve": one(self.cve), "mitre": one(self.mitre), "notes": list(self.notes)}


def build_providers(settings: Settings, cfg: ThreatIntelConfig, nvd_api_key: str = "") -> ProviderSet:
    """Choose providers from TI_PROVIDER / TI_API_KEY (PRD section 41) plus the YAML knobs. Never raises."""
    ps = ProviderSet()
    choice = (settings.ti_provider or "").strip().lower()
    if not choice:
        ps.notes.append("No reputation provider configured (TI_PROVIDER is empty); IP/domain indicators will be reported as not queried.")
    elif choice == "otx":
        if settings.ti_api_key:
            ps.reputation, ps.reputation_status = OTXProvider(settings.ti_api_key, cfg["otx"]["timeout_s"]), "ok"
        else:
            ps.reputation_status = "missing_api_key"
            ps.notes.append("TI_PROVIDER=otx but TI_API_KEY is empty; IP/domain lookups are skipped.")
    elif choice == "synthetic_demo":
        ps.reputation, ps.reputation_status = SyntheticDemoProvider(), "ok"
        ps.notes.append("TI_PROVIDER=synthetic_demo: IP results are SYNTHETIC demo records, not real intelligence.")
    else:
        ps.reputation_status = "unknown_provider"
        ps.notes.append(f"TI_PROVIDER '{clean_text(choice, 40)}' is not supported; supported: otx, synthetic_demo.")
    nvd = cfg["nvd"]
    if nvd["enabled"]:
        ps.cve = NVDProvider(nvd_api_key, nvd["timeout_s"], nvd["rate_limit_per_30s_without_key"], nvd["rate_limit_per_30s_with_key"])
    if cfg["mitre"]["enabled"]:
        ps.mitre = MitreProvider()
    return ps
