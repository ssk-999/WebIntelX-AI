"""Threat-intelligence enrichment of an incident (PRD section 16, FR-13, AC-11, NFR Reliability).

Flow: extract indicators -> look each one up with the matching provider -> store the structured report under
`incident.details["threat_intel"]` (a key this module owns; correlation preserves it on re-runs).

Guarantees (PRD):
  * A provider failure, timeout or rate limit never ends the investigation: every lookup is isolated, the run
    carries on, and the failure is shown with its status. `run_enrichment` never raises.
  * No-Evidence Rule: an indicator with nothing usable gets an explicit "no threat-intelligence evidence was
    found" result that does not claim safety or maliciousness. Nothing is invented.
  * Private/reserved/documentation/privacy-masked IPs are never sent to an external provider
    (indicators.ips.query_non_public can relax this; masked values are never sent).
  * Credentials are never logged or stored in results.

PRD does not specify the following; using these implementation assumptions:
  * On demand (like ML and correlation), not per ingest batch: the orchestrator (M8) and the API call it.
  * One run replaces the previous `threat_intel` report; a short in-process TTL cache protects free-tier quotas.
    Only real answers (evidence / no evidence) are cached, never failures, and local providers need no cache.
  * Sequential lookups under a total time budget (`deadline_s`); once spent, remaining network lookups are
    reported as skipped (status `timeout`) instead of blocking the request.
  * Enrichment sends only the indicator value (an IP, CVE id or domain) to the configured provider. By choosing
    TI_PROVIDER the operator accepts that an incident's source IP is shared with that third party.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import replace
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.correlation.engine import load_findings
from app.database.models import Event, Incident, Website
from app.threat_intel.base import (
    ABSENCE_NOTE, ERROR, EVIDENCE_FOUND, FAILURE_STATUSES, IND_DOMAIN, IND_IP, MITRE_NOTE, NOT_APPLICABLE,
    NOT_CONFIGURED, NO_EVIDENCE, TIMEOUT, Indicator, TIResult, now_iso, parse_ip,
)
from app.threat_intel.config import ThreatIntelConfig, get_ti_config
from app.threat_intel.extract import extract_indicators
from app.threat_intel.providers import ProviderSet, build_providers

log = logging.getLogger("webintelx.threat_intel")
_CHUNK = 500
_CACHE: dict[tuple[str, str, str], tuple[float, TIResult]] = {}
_CACHE_LOCK = threading.Lock()
MAX_CACHE_ENTRIES = 1000


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def make_client() -> httpx.Client:
    """One client per run. Redirects are not followed: provider URLs are fixed and a redirect would be unexpected."""
    return httpx.Client(follow_redirects=False, headers={"User-Agent": "WebIntelX-AI/0.6 (security investigation; contact: site operator)"})


def _cache_get(key: tuple[str, str, str], ttl: float) -> TIResult | None:
    if ttl <= 0:
        return None
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and time.monotonic() - hit[0] <= ttl:
            return replace(hit[1], cached=True)
        _CACHE.pop(key, None)
    return None


def _cache_put(key: tuple[str, str, str], res: TIResult, ttl: float) -> None:
    if ttl <= 0 or res.status not in (EVIDENCE_FOUND, NO_EVIDENCE):
        return
    with _CACHE_LOCK:
        if len(_CACHE) >= MAX_CACHE_ENTRIES:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = (time.monotonic(), res)


def _not_configured(ind: Indicator, ps: ProviderSet) -> TIResult:
    if ind.type in (IND_IP, IND_DOMAIN):
        why = {"missing_api_key": "the selected provider has no API key (TI_API_KEY)", "unknown_provider": "TI_PROVIDER names an unsupported provider"}.get(
            ps.reputation_status, "no reputation provider is configured (TI_PROVIDER)")
        provider = "none"
    else:
        why, provider = "this lookup is disabled in the threat-intelligence configuration", "none"
    return TIResult(ind.type, ind.value, provider, NOT_CONFIGURED,
                    f"Nothing was queried for {ind.value} because {why}. No threat-intelligence evidence is available. {ABSENCE_NOTE}",
                    context=dict(ind.context))


def _not_applicable(ind: Indicator, provider: str) -> TIResult:
    return TIResult(ind.type, ind.value, provider, NOT_APPLICABLE,
                    f"{ind.value} is not a single public internet address (private, reserved, documentation-range or privacy-masked), "
                    f"so it was not sent to an external provider. No threat-intelligence evidence was found. {ABSENCE_NOTE}",
                    context=dict(ind.context))


def _lookup(ind: Indicator, ps: ProviderSet, cfg: ThreatIntelConfig, client: httpx.Client | None, started: float) -> TIResult:
    provider = ps.for_type(ind.type)
    if provider is None:
        return _not_configured(ind, ps)
    if ind.type == IND_IP and provider.requires_public_ip:
        valid = parse_ip(ind.value) is not None
        if not valid or (not cfg["indicators"]["ips"]["query_non_public"] and not parse_ip(ind.value).is_global):  # type: ignore[union-attr]
            return _not_applicable(ind, provider.name)
    ttl = float(cfg["cache_ttl_s"])
    key = (provider.name, ind.type, ind.value)
    if provider.network:
        cached = _cache_get(key, ttl)
        if cached is not None:
            cached.context = dict(ind.context)
            return cached
        if time.monotonic() - started >= float(cfg["deadline_s"]):
            return TIResult(ind.type, ind.value, provider.name, TIMEOUT,
                            f"Skipped: the enrichment time budget ({cfg['deadline_s']} s) was used up before {ind.value} was queried. No threat-intelligence evidence is available for it from this run.",
                            context=dict(ind.context))
    try:
        res = provider.lookup(ind, client)  # type: ignore[arg-type]  # local providers never use the client
    except Exception as exc:  # a provider bug must never end the investigation
        log.error("provider %s failed on a %s indicator: %s", provider.name, ind.type, type(exc).__name__)
        res = TIResult(ind.type, ind.value, provider.name, ERROR,
                       f"{provider.name} failed unexpectedly ({type(exc).__name__}); no threat-intelligence evidence is available from it.")
    res.context = {**res.context, **ind.context}
    if provider.network:
        _cache_put(key, res, ttl)
    return res


def build_report(results: list[TIResult], ps: ProviderSet, dropped: dict[str, int], retrieved_at: str, indicators_found: int) -> dict[str, Any]:
    counts = dict(sorted(Counter(r.status for r in results).items()))
    status = "no_indicators" if indicators_found == 0 else ("partial" if any(r.status in FAILURE_STATUSES for r in results) else "ok")
    notes = list(ps.notes)
    for kind, n in sorted(dropped.items()):
        notes.append(f"{n} {kind} indicator(s) were not queried because indicators.max_per_incident was reached.")
    return {
        "basis": "external_providers_and_local_reference", "status": status, "retrieved_at": retrieved_at,
        "providers": ps.public(), "indicators_found": indicators_found, "indicators_checked": len(results),
        "counts": counts, "contains_synthetic": any(r.synthetic for r in results), "dropped": dropped,
        "results": [r.to_dict() for r in results], "notes": notes,
        "disclaimers": [ABSENCE_NOTE, MITRE_NOTE,
                        "Threat-intelligence results are third-party context. They are not an AI conclusion and not proof of an attack."],
    }


def _incident_events(db: Session, inc: Incident) -> list[Event]:
    ids = list((inc.details or {}).get("event_ids") or [])
    out: list[Event] = []
    for i in range(0, len(ids), _CHUNK):
        out += list(db.scalars(select(Event).where(Event.website_id == inc.website_id, Event.event_id.in_(ids[i:i + _CHUNK]))))
    return sorted(out, key=lambda e: (e.timestamp, e.event_id))


def run_enrichment(db: Session, incident: Incident, *, settings: Settings | None = None, cfg: ThreatIntelConfig | None = None,
                   client: httpx.Client | None = None, nvd_api_key: str | None = None) -> dict[str, Any]:
    """Enrich one incident and store the report. Never raises. Returns the report (with `status`)."""
    cfg = cfg or get_ti_config()
    settings = settings or get_settings()
    if not cfg["enabled"]:
        return {"status": "disabled", "incident_id": incident.incident_id, "results": [],
                "notes": ["Threat-intelligence enrichment is disabled in configuration; nothing was written."]}
    own_client = client is None
    try:
        ps = build_providers(settings, cfg, settings.nvd_api_key if nvd_api_key is None else nvd_api_key)
        events = _incident_events(db, incident)
        findings = load_findings(db, incident.website_id, [e.event_id for e in events])
        site = db.get(Website, incident.website_id)
        indicators, dropped = extract_indicators(incident, events, findings, site_domain=site.domain if site else "", cfg=cfg)
        if client is None and any((p := ps.for_type(i.type)) is not None and p.network for i in indicators):
            client = make_client()          # only when a network lookup is really needed; local providers ignore the client
        started = time.monotonic()
        results = [_lookup(i, ps, cfg, client, started) for i in indicators]
        report = build_report(results, ps, dropped, now_iso(), len(indicators))
        incident.details = {**(incident.details or {}), "threat_intel": report}   # new dict object so the JSON change is detected
        db.commit()
        log.info("threat intel for %s: %s indicators, statuses=%s", incident.incident_id, len(results), report["counts"])
        return {"incident_id": incident.incident_id, **report}
    except Exception as exc:  # never fail the investigation (PRD NFR Reliability)
        db.rollback()
        log.error("threat-intel enrichment failed for %s: %s", incident.incident_id, type(exc).__name__)
        return {"status": "error", "incident_id": incident.incident_id, "results": [],
                "notes": [f"Enrichment failed ({type(exc).__name__}); nothing was written. The rest of the investigation is unaffected."]}
    finally:
        if own_client and client is not None:
            client.close()


def stored_report(incident: Incident) -> dict[str, Any]:
    ti = (incident.details or {}).get("threat_intel")
    if not isinstance(ti, dict):
        return {"incident_id": incident.incident_id, "status": "not_run", "results": [],
                "notes": ["Threat-intelligence enrichment has not been run for this incident."]}
    return {"incident_id": incident.incident_id, **ti}
