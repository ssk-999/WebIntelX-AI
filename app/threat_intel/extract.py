"""Indicator extraction for an incident (PRD section 16: IP, domain, CVE, MITRE ATT&CK).

Deterministic, no LLM, no network. Only values that are actually present in the incident's stored data are
extracted (PRD: "map only when a valid CVE or technology signal is present"):

  ip         the incident's correlated source IPs (they may be privacy-masked; the service decides what may be sent out)
  cve        valid `CVE-YYYY-NNNN+` identifiers found in the (already masked) request targets of the incident's events
  domain     `referrer_host` of SDK page views, only when indicators.domains.enabled (off by default: visitor data)
  attack_technique  technique ids already attached to the incident's findings (rule `mitre_reference`)

PRD does not specify a "technology signal" source; the platform collects no technology/version data, so none is
extracted (stated, not invented).
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.threat_intel.base import IND_CVE, IND_DOMAIN, IND_IP, IND_TECHNIQUE, Indicator, find_cves, normalize_domain
from app.threat_intel.config import ThreatIntelConfig

MAX_CONTEXT_IDS = 20


def _add(bucket: dict[str, list[str]], key: str, ref: str) -> None:
    ids = bucket.setdefault(key, [])
    if ref not in ids and len(ids) < MAX_CONTEXT_IDS:
        ids.append(ref)


def extract_indicators(incident: Any, events: Sequence, findings: Sequence, *, site_domain: str,
                       cfg: ThreatIntelConfig) -> tuple[list[Indicator], dict[str, int]]:
    """Return (indicators, dropped) where `dropped[type]` counts indicators cut by `indicators.max_per_incident`."""
    icfg = cfg["indicators"]
    cap = icfg["max_per_incident"]
    out: list[Indicator] = []
    dropped: dict[str, int] = {}

    def take(kind: str, items: list[Indicator]) -> None:
        out.extend(items[:cap])
        if len(items) > cap:
            dropped[kind] = len(items) - cap

    if icfg["ips"]["enabled"]:
        ips = (((incident.details or {}).get("entities") or {}).get("source_ips")) or []
        seen = list(dict.fromkeys(str(i) for i in ips if i))
        take(IND_IP, [Indicator(IND_IP, i, {"source": "incident source IP"}) for i in sorted(seen)])

    if icfg["cves"]["enabled"]:
        cves: dict[str, list[str]] = {}
        for e in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
            for cve in find_cves(e.endpoint or ""):
                _add(cves, cve, e.event_id)
        take(IND_CVE, [Indicator(IND_CVE, c, {"event_ids": ids}) for c, ids in sorted(cves.items())])

    if icfg["domains"]["enabled"]:
        own = (site_domain or "").lower().rstrip(".")
        doms: dict[str, list[str]] = {}
        for e in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
            host = (((e.processed_data or {}).get("attributes") or {}).get("referrer_host"))
            d = normalize_domain(host) if isinstance(host, str) else None
            if d and not (own and (d == own or d.endswith("." + own))):
                _add(doms, d, e.event_id)
        take(IND_DOMAIN, [Indicator(IND_DOMAIN, d, {"event_ids": ids}) for d, ids in sorted(doms.items())])

    techniques: dict[str, list[str]] = {}
    for f in findings:
        ref = (f.evidence or {}).get("mitre_reference")
        tid = ref.get("technique_id") if isinstance(ref, dict) else None
        if isinstance(tid, str) and tid.strip():
            _add(techniques, tid.strip().upper(), f.finding_id)
    out.extend(Indicator(IND_TECHNIQUE, t, {"finding_ids": ids}) for t, ids in sorted(techniques.items()))
    return out, dropped
