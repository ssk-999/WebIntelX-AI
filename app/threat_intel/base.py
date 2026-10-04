"""Threat-intelligence types shared by every provider (PRD section 16).

PRD rules enforced here:
  * No-Evidence Rule: when a provider returns nothing usable, the result says so explicitly and states that the
    absence of evidence is NOT a claim of safety or maliciousness.
  * Never invent reputation / CVE evidence: a result carries only fields a provider actually returned.
  * Every result shows its source and status. Synthetic demo results are flagged and can never be mistaken
    for real intelligence.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

# Result statuses. Only `evidence_found` carries evidence; every other status means "nothing to rely on" and
# must never be turned into a claim of safety or maliciousness.
EVIDENCE_FOUND = "evidence_found"
NO_EVIDENCE = "no_evidence"            # the provider answered and had nothing on this indicator
NOT_CONFIGURED = "not_configured"      # no provider is set up for this indicator type; nothing was queried
NOT_APPLICABLE = "not_applicable"      # the indicator must not be sent out (private/reserved/masked); nothing was queried
RATE_LIMITED = "rate_limited"
TIMEOUT = "timeout"
ERROR = "error"
STATUSES = (EVIDENCE_FOUND, NO_EVIDENCE, NOT_CONFIGURED, NOT_APPLICABLE, RATE_LIMITED, TIMEOUT, ERROR)
FAILURE_STATUSES = (RATE_LIMITED, TIMEOUT, ERROR)

IND_IP, IND_DOMAIN, IND_CVE, IND_TECHNIQUE = "ip", "domain", "cve", "attack_technique"

ABSENCE_NOTE = "Absence of threat-intelligence evidence is not a claim that the indicator is safe, and not a claim that it is malicious."
MITRE_NOTE = "ATT&CK mapping is reference context for analysts, not proof that the technique was used."

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CVE_FIND_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_text(value: Any, limit: int = 300) -> str:
    """Third-party text is untrusted: strip control characters, collapse whitespace, truncate. (The UI must still render it as text.)"""
    s = _CTRL_RE.sub(" ", str(value))
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "\u2026"


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None


def is_public_ip(value: str) -> bool:
    ip = parse_ip(value)
    return bool(ip and ip.is_global)


def normalize_cve(value: str) -> str | None:
    v = (value or "").strip().upper()
    return v if _CVE_RE.match(v) else None


def find_cves(text: str) -> list[str]:
    return [m.upper() for m in _CVE_FIND_RE.findall(text or "")]


def normalize_domain(value: str) -> str | None:
    v = (value or "").strip().lower().rstrip(".")
    return v if _DOMAIN_RE.match(v) else None


@dataclass
class Indicator:
    type: str
    value: str
    context: dict[str, Any] = field(default_factory=dict)   # e.g. event_ids / finding_ids the indicator came from (traceability)


@dataclass
class TIResult:
    indicator_type: str
    indicator: str
    provider: str
    status: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)       # only fields the provider actually returned
    source: str = ""                                         # provider URL or local-table label
    synthetic: bool = False
    cached: bool = False
    retrieved_at: str = field(default_factory=now_iso)
    limitations: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_type": self.indicator_type, "indicator": self.indicator, "provider": self.provider,
            "status": self.status, "evidence_status": "evidence" if self.status == EVIDENCE_FOUND else "no_evidence",
            "summary": self.summary, "data": self.data, "source": self.source, "synthetic": self.synthetic,
            "cached": self.cached, "retrieved_at": self.retrieved_at, "limitations": self.limitations, "context": self.context,
        }


def no_evidence_text(indicator: str, provider: str) -> str:
    return f"No threat-intelligence evidence was found for {indicator} from {provider}. {ABSENCE_NOTE}"


class Provider:
    """A pluggable enrichment source (PRD NFR Modularity). Subclasses implement `lookup`; they may raise nothing
    the service cannot handle, but the service wraps every call so a provider bug never ends an investigation."""

    name = "base"
    indicator_types: tuple[str, ...] = ()
    synthetic = False
    requires_public_ip = True      # real external providers must never receive private/reserved/masked addresses
    network = True                 # False for local providers (no timeout budget, no cache needed)

    def supports(self, indicator_type: str) -> bool:
        return indicator_type in self.indicator_types

    def lookup(self, ind: Indicator, client: httpx.Client) -> TIResult:  # pragma: no cover - interface
        raise NotImplementedError

    def public_status(self) -> dict[str, Any]:
        return {"name": self.name, "indicator_types": list(self.indicator_types), "synthetic": self.synthetic, "network": self.network}
