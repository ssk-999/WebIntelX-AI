"""Deterministic event-correlation engine (PRD section 15, FR-12, AC-09).

The PRD wants correlation to be the *evidence backbone*: deterministic rules relate events, and agents later
interpret (never redefine) those relationships. So this module has no LLM, no network and no randomness.

Pipeline
  1. Seeds   = events that carry a finding or are cited as evidence by one (rule engine M3 and ML model M4).
  2. Links   = per entity (source IP, session, authenticated user) the time-sorted events are chained when the gap
               is within a configured limit. Chaining (not all-pairs) keeps the record count linear.
               Extra links: same_endpoint / similar_behavior (evidence only, never merge clusters) and
               attack_sequence (a recognised ordered chain of stages).
  3. Clusters = connected components over the *merge* link types that contain at least one seed.
  4. Incident candidates = clusters passing a configured test. Incident rows are created in DETECTED state with NO
     risk (risk scoring is milestone 7; agents are milestone 8).

PRD correlation dimensions -> implementation
  temporal proximity ....... gates every link (max_gap_s) and lowers its strength; not a separate link type
  same source IP ........... same_ip
  same session ID .......... same_session
  same user/account ........ same_user (authenticated principal only, see below)
  same endpoint/resource ... same_endpoint (evidence only)
  similar behavioural pattern similar_behavior (evidence only)
  recognisable attack sequence attack_sequence

PRD does not specify the following; using these implementation assumptions:
  * `login_failure` events carry the *attempted* account, not an authenticated principal, so they never create
    same_user links (otherwise one guessed account would pull that user's normal sessions into an incident).
  * Link direction: `event_id` is the earlier event, `related_event_id` the later one.
  * Strength = base[type] * (1 - 0.5 * min(gap / max_gap[type], 1)); a documented heuristic, not a probability.
  * Re-running replaces the derived correlation rows. Incidents are matched to clusters by event overlap so an
    incident keeps its id, status, risk and feedback while its cluster grows. An incident whose cluster vanished
    is deleted only if it is still untouched (DETECTED, no feedback); otherwise it is kept and flagged `stale`.
"""
from __future__ import annotations

import hashlib
import logging
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.correlation.config import CorrelationConfig, get_correlation_config
from app.database.models import Correlation, Event, Feedback, Finding, Incident
from app.detection.engine import load_events

log = logging.getLogger("webintelx.correlation")
_CHUNK = 500

# --------------------------------------------------------------------------------------- attack stages
STAGE_ORDER = ("abnormal_navigation", "credential_attack", "authentication_success", "new_session",
               "sensitive_access", "attack_indicator")
STAGE_LABEL = {
    "abnormal_navigation": "abnormal navigation", "credential_attack": "failed-login burst",
    "authentication_success": "successful login", "new_session": "new session",
    "sensitive_access": "sensitive endpoint access", "attack_indicator": "attack-indicator request",
}
_NAV_CATEGORIES = {"non_human_navigation", "recon_path_probing", "automation_indicator", "high_request_rate"}
_AUTH_FAIL_CATEGORIES = {"brute_force_indicator", "multi_account_auth_failures"}


# ------------------------------------------------------------------------------------------ data types
@dataclass(frozen=True)
class FindingView:
    """What correlation needs from a Finding row (keeps the core independent of the ORM)."""

    finding_id: str
    event_id: str
    agent_name: str
    finding_type: str
    confidence: float
    rule_id: str
    category: str
    title: str
    event_ids: tuple[str, ...]


def finding_view(f: Finding) -> FindingView:
    ev = f.evidence or {}
    return FindingView(f.finding_id, f.event_id, f.agent_name, f.finding_type, float(f.confidence or 0.0),
                       str(ev.get("rule_id") or ""), str(ev.get("category") or f.finding_type),
                       str(ev.get("rule_title") or ev.get("category") or f.finding_type),
                       tuple(ev.get("event_ids") or ()))


@dataclass(frozen=True)
class Link:
    event_id: str            # earlier event
    related_event_id: str    # later event
    relationship_type: str
    strength: float


@dataclass
class Cluster:
    cluster_id: str
    event_ids: list[str]                      # time-sorted
    seed_event_ids: list[str]
    links: list[Link]
    findings: list[FindingView]
    stages: dict[str, list[str]]              # stage -> event ids (time-sorted)
    first_seen: datetime
    last_seen: datetime
    source_ips: list[str]
    session_ids: list[str]
    user_ids: list[str]
    categories: list[str]
    max_confidence: float
    links_truncated: bool = False
    is_incident_candidate: bool = False
    title: str = ""
    affected_resources: list[str] = field(default_factory=list)

    def link_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(l.relationship_type for l in self.links).items()))


@dataclass
class CorrelationResult:
    clusters: list[Cluster]
    events_considered: int
    seed_events: int


# ------------------------------------------------------------------------------------------- helpers
class _DSU:
    def __init__(self) -> None:
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)  # deterministic root


def _strength(rel: str, gap_s: float, cfg: CorrelationConfig) -> float:
    base, limit = cfg["base_strength"][rel], cfg["max_gap_s"].get(rel) or 1
    return round(base * (1 - 0.5 * min(max(gap_s, 0.0) / limit, 1.0)), 3)


def _path(e) -> str | None:
    return (e.features or {}).get("path")


def _chain(events: Sequence, rel: str, cfg: CorrelationConfig, *, skip=None) -> list[Link]:
    """Link consecutive events (already one entity, time-sorted) when the gap is within the configured limit."""
    out: list[Link] = []
    limit = cfg["max_gap_s"][rel]
    for a, b in zip(events, events[1:]):
        gap = (b.timestamp - a.timestamp).total_seconds()
        if gap <= limit and not (skip and skip(a, b)):
            out.append(Link(a.event_id, b.event_id, rel, _strength(rel, gap, cfg)))
    return out


def _sort_key(e) -> tuple:
    return (e.timestamp, e.event_id)


def stage_of(e, cited_cats: dict[str, set[str]]) -> str | None:
    """Stage of one event in the recognisable attack chain, from its type and the findings that cite it."""
    cats, f = cited_cats.get(e.event_id, set()), e.features or {}
    if e.event_type == "waf_alert" or "attack_indicator_cat" in cats:
        return "attack_indicator"
    if f.get("is_sensitive_endpoint"):
        return "sensitive_access"
    if e.event_type == "session_created":
        return "new_session"
    if e.event_type == "login_success":
        return "authentication_success"
    if e.event_type == "login_failure" and cats & _AUTH_FAIL_CATEGORIES:
        return "credential_attack"
    if e.event_type == "page_view" and cats & _NAV_CATEGORIES:
        return "abnormal_navigation"
    return None


def _cited_categories(findings: Sequence[FindingView], known: set[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for fv in findings:
        cats = {fv.category} | ({"attack_indicator_cat"} if fv.finding_type == "attack_indicator" else set())
        for eid in {fv.event_id, *fv.event_ids}:
            if eid in known:
                out[eid] |= cats
    return out


def detect_stages(events: Sequence, findings: Sequence[FindingView]) -> dict[str, list[str]]:
    cited = _cited_categories(findings, {e.event_id for e in events})
    stages: dict[str, list[str]] = {}
    for e in sorted(events, key=_sort_key):
        s = stage_of(e, cited)
        if s:
            stages.setdefault(s, []).append(e.event_id)
    # A session_created / login_success is only part of the chain once a credential attack or navigation precedes it
    # in this cluster; otherwise ordinary logins would be labelled as attack stages.
    if not ({"credential_attack", "abnormal_navigation", "attack_indicator"} & stages.keys()):
        return {}
    return {s: stages[s] for s in STAGE_ORDER if s in stages}


def _sequence_links(by_id: dict[str, Any], stages: dict[str, list[str]], cfg: CorrelationConfig) -> list[Link]:
    present = [s for s in STAGE_ORDER if s in stages]
    links: list[Link] = []
    for prev, nxt in zip(present, present[1:]):
        first_next = by_id[stages[nxt][0]]
        candidates = [by_id[i] for i in stages[prev] if by_id[i].timestamp <= first_next.timestamp]
        if not candidates:
            continue
        last_prev = max(candidates, key=_sort_key)
        if not ((last_prev.source_ip and last_prev.source_ip == first_next.source_ip)
                or (last_prev.user_id and last_prev.user_id == first_next.user_id)):
            continue  # a sequence must be anchored to one actor (same IP or same account)
        gap = (first_next.timestamp - last_prev.timestamp).total_seconds()
        links.append(Link(last_prev.event_id, first_next.event_id, "attack_sequence", _strength("attack_sequence", gap, cfg)))
    return links


# ----------------------------------------------------------------------------------------------- core
def correlate(events: Sequence, findings: Sequence[FindingView], cfg: CorrelationConfig | None = None) -> CorrelationResult:
    """Pure function: events + findings -> clusters. Deterministic for identical input."""
    cfg = cfg or get_correlation_config()
    by_id = {e.event_id: e for e in events}
    fmap: dict[str, list[FindingView]] = defaultdict(list)
    seeds: set[str] = set()
    for fv in findings:
        if fv.event_id not in by_id:
            continue
        fmap[fv.event_id].append(fv)
        seeds.add(fv.event_id)
        seeds.update(i for i in fv.event_ids if i in by_id)
    if not seeds:
        return CorrelationResult([], len(by_id), 0)

    # Entities that appear on seed events. Failed logins do not identify a user (see module docstring).
    s_ips = {by_id[i].source_ip for i in seeds if by_id[i].source_ip}
    s_sids = {by_id[i].session_id for i in seeds if by_id[i].session_id}
    s_users = {by_id[i].user_id for i in seeds if by_id[i].user_id and by_id[i].event_type != "login_failure"}

    groups: dict[tuple[str, str], list] = defaultdict(list)
    for e in sorted(events, key=_sort_key):
        if e.source_ip in s_ips:
            groups[("same_ip", e.source_ip)].append(e)
        if e.session_id in s_sids:
            groups[("same_session", e.session_id)].append(e)
        if e.user_id in s_users and e.event_type != "login_failure":
            groups[("same_user", e.user_id)].append(e)

    all_links: list[Link] = []
    for (rel, _key), evs in sorted(groups.items()):
        all_links += _chain(evs, rel, cfg)

    merge = set(cfg["merge_types"])
    dsu = _DSU()
    for l in all_links:
        if l.relationship_type in merge:
            dsu.union(l.event_id, l.related_event_id)
    for sid in seeds:                      # a seed with no neighbours is still its own (single-event) cluster
        dsu.find(sid)

    members: dict[str, set[str]] = defaultdict(set)
    linked_ids = {i for l in all_links for i in (l.event_id, l.related_event_id)} | seeds
    for eid in linked_ids:
        members[dsu.find(eid)].add(eid)

    clusters: list[Cluster] = []
    for _root, ids in members.items():
        if not ids & seeds:
            continue
        evs = sorted((by_id[i] for i in ids), key=_sort_key)
        cl_findings = sorted({fv.finding_id: fv for i in ids for fv in fmap.get(i, [])}.values(), key=lambda f: f.finding_id)
        links = [l for l in all_links if l.event_id in ids and l.related_event_id in ids and l.relationship_type in merge]
        stages = detect_stages(evs, cl_findings)
        links += _sequence_links(by_id, stages, cfg)

        # evidence-only relationships inside the cluster (never used to merge clusters)
        by_path: dict[str, list] = defaultdict(list)
        for e in evs:
            if _path(e):
                by_path[_path(e)].append(e)
        for _p, pe in sorted(by_path.items()):
            links += _chain(pe, "same_endpoint", cfg, skip=lambda a, b: (a.event_type, a.session_id) == (b.event_type, b.session_id))
        by_cat: dict[str, list] = defaultdict(list)
        for fv in cl_findings:
            by_cat[fv.category].append(by_id[fv.event_id])
        for _c, ce in sorted(by_cat.items()):
            ce = sorted({e.event_id: e for e in ce}.values(), key=_sort_key)
            links += _chain(ce, "similar_behavior", cfg, skip=lambda a, b: a.session_id == b.session_id)

        links = sorted(set(links), key=lambda l: (by_id[l.event_id].timestamp, l.event_id, l.related_event_id, l.relationship_type))
        truncated = len(links) > cfg["max_links_per_cluster"]
        if truncated:
            # keep the strongest evidence first, always keeping the attack sequence
            keep = sorted(links, key=lambda l: (l.relationship_type != "attack_sequence", -l.strength, l.event_id, l.related_event_id))
            links = sorted(keep[: cfg["max_links_per_cluster"]], key=lambda l: (by_id[l.event_id].timestamp, l.event_id, l.related_event_id, l.relationship_type))

        cats = sorted({f.category for f in cl_findings})
        c = Cluster(
            cluster_id="clu_" + hashlib.sha256(evs[0].event_id.encode()).hexdigest()[:12],
            event_ids=[e.event_id for e in evs], seed_event_ids=sorted(ids & seeds), links=links, findings=cl_findings,
            stages=stages, first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp,
            source_ips=sorted({e.source_ip for e in evs if e.source_ip}), session_ids=sorted({e.session_id for e in evs if e.session_id}),
            user_ids=sorted({e.user_id for e in evs if e.user_id and e.event_type != "login_failure"}),
            categories=cats, max_confidence=max((f.confidence for f in cl_findings), default=0.0), links_truncated=truncated,
        )
        inc = cfg["incident"]
        c.is_incident_candidate = bool(cl_findings) and (c.max_confidence >= inc["min_max_finding_confidence"]
                                                         or len(cats) >= inc["min_distinct_categories"])
        c.title, c.affected_resources = _title(c, by_id), _affected(c, by_id)
        clusters.append(c)
    clusters.sort(key=lambda c: (-c.max_confidence, c.first_seen, c.cluster_id))
    return CorrelationResult(clusters, len(by_id), len(seeds))


def _source_label(c: Cluster) -> str:
    return c.source_ips[0] if len(c.source_ips) == 1 else (f"{len(c.source_ips)} sources" if c.source_ips else "an unidentified source")


def _title(c: Cluster, by_id: dict[str, Any]) -> str:
    """Deterministic, hedged title (basis: template - never an LLM, never a verdict)."""
    if len(c.stages) >= 2:
        return f"Suspicious activity chain from {_source_label(c)}: " + " \u2192 ".join(STAGE_LABEL[s] for s in c.stages)
    best = max(c.findings, key=lambda f: (f.confidence, f.rule_id), default=None)
    return f"{best.title} from {_source_label(c)}" if best else f"Suspicious activity from {_source_label(c)}"


def _affected(c: Cluster, by_id: dict[str, Any], limit: int = 5) -> list[str]:
    """Paths (no query strings) of the sensitive / attack-indicator events, else the most-targeted finding paths."""
    paths: list[str] = []
    for stage in ("sensitive_access", "attack_indicator"):
        paths += [p for i in c.stages.get(stage, []) if (p := _path(by_id[i]))]
    if not paths:
        anchor_paths = [p for f in c.findings if (p := _path(by_id[f.event_id]))]
        paths = [p for p, _ in Counter(anchor_paths).most_common()]
    return list(dict.fromkeys(paths))[:limit]


# ------------------------------------------------------------------------------------------------ DB
@dataclass
class CorrelationReport:
    status: str = "ok"                         # ok | no_findings | disabled | error
    error: str | None = None
    events_considered: int = 0
    suspicious_events: int = 0
    clusters: int = 0
    potential_incidents: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    incidents_removed: int = 0
    incidents_stale: int = 0
    correlation_records: int = 0
    cluster_summaries: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["note"] = ("Counts describe THIS website's stored data only; they are not production performance claims. "
                     "Incidents are created without risk: risk scoring is a later milestone.")
        return d


def _chunks(seq: Sequence, n: int = _CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def load_findings(db: Session, website_id: str, event_ids: Sequence[str]) -> list[Finding]:
    out: list[Finding] = []
    for chunk in _chunks(list(event_ids)):
        out += list(db.scalars(select(Finding).where(Finding.event_id.in_(chunk))))
    return out  # callers pass only this website's event ids (website isolation)


def _details(c: Cluster, cfg: CorrelationConfig) -> dict[str, Any]:
    cap = cfg["max_event_ids_in_details"]
    return {
        "basis": "deterministic_correlation", "title_basis": "rule_template", "cluster_id": c.cluster_id,
        "event_count": len(c.event_ids), "event_ids": c.event_ids[:cap], "event_ids_truncated": len(c.event_ids) > cap,
        "seed_event_count": len(c.seed_event_ids), "finding_ids": [f.finding_id for f in c.findings],
        "rule_ids": sorted({f.rule_id for f in c.findings if f.rule_id}), "categories": c.categories,
        "agents": sorted({f.agent_name for f in c.findings}), "max_finding_confidence": c.max_confidence,
        "stages": {s: {"event_count": len(ids), "first_event_id": ids[0], "last_event_id": ids[-1]} for s, ids in c.stages.items()},
        "entities": {"source_ips": c.source_ips, "session_ids": c.session_ids, "user_ids": c.user_ids[:20]},
        "first_seen": c.first_seen.isoformat(), "last_seen": c.last_seen.isoformat(),
        "affected_resources": c.affected_resources, "link_counts": c.link_counts(), "links_truncated": c.links_truncated,
        "limitations": [
            "Correlation shows that events are related by shared IP/session/account and time; it does not prove one actor or intent.",
            "Shared IPs (NAT, proxies, truncated/hashed IP modes) can group unrelated users.",
            "Risk has not been scored yet and no AI investigation has run for this incident.",
        ],
    }


def run_correlation(db: Session, website_id: str, *, cfg: CorrelationConfig | None = None, now: datetime | None = None) -> CorrelationReport:
    """Correlate this website's recent events and (re)create incident candidates. Never raises."""
    cfg = cfg or get_correlation_config()
    if not cfg["enabled"]:
        return CorrelationReport(status="disabled")
    now = now or datetime.now(timezone.utc)
    try:
        events = load_events(db, website_id, since=now - timedelta(hours=cfg["lookback_hours"]))
        findings = [finding_view(f) for f in load_findings(db, website_id, [e.event_id for e in events])]
        result = correlate(events, findings, cfg)
        rep = CorrelationReport(events_considered=result.events_considered, suspicious_events=result.seed_events,
                                clusters=len(result.clusters))
        if not result.clusters:
            rep.status = "no_findings"

        existing = list(db.scalars(select(Incident).where(Incident.website_id == website_id)))
        sets = {i.incident_id: set((i.details or {}).get("event_ids") or []) for i in existing}
        free = {i.incident_id: i for i in existing}
        candidates = [c for c in result.clusters if c.is_incident_candidate]
        rep.potential_incidents = len(candidates)

        matched: dict[str, Incident | None] = {}
        for c in sorted(candidates, key=lambda c: -len(c.event_ids)):     # greedy by overlap, deterministic
            ids = set(c.event_ids)
            best = max(((len(ids & sets[iid]), iid) for iid in free), default=(0, None))
            if best[0] > 0:
                matched[c.cluster_id] = free.pop(best[1])
            else:
                matched[c.cluster_id] = None

        # Remove derived correlations we are about to regenerate (unattached + those of matched/removed incidents).
        touched = {i.incident_id for i in matched.values() if i is not None}
        removable = []
        for inc in free.values():
            has_fb = db.scalar(select(Feedback.feedback_id).where(Feedback.incident_id == inc.incident_id).limit(1)) is not None
            if inc.status == "DETECTED" and not has_fb and (inc.details or {}).get("basis") == "deterministic_correlation":
                removable.append(inc)
            elif not (inc.details or {}).get("stale"):
                inc.details = {**(inc.details or {}), "stale": True}
                rep.incidents_stale += 1
        gone = {i.incident_id for i in removable}
        db.execute(delete(Correlation).where(Correlation.website_id == website_id, Correlation.incident_id.is_(None)))
        for chunk in _chunks(sorted(touched | gone)):
            db.execute(delete(Correlation).where(Correlation.website_id == website_id, Correlation.incident_id.in_(chunk)))
        for inc in removable:
            db.delete(inc)
        rep.incidents_removed = len(removable)
        db.flush()

        for c in result.clusters:
            inc = matched.get(c.cluster_id) if c.is_incident_candidate else None
            if c.is_incident_candidate:
                details = _details(c, cfg)
                if inc is None:
                    inc = Incident(website_id=website_id, title=c.title[:300], status="DETECTED", details=details)
                    db.add(inc)
                    db.flush()
                    rep.incidents_created += 1
                else:
                    # Overwrite only the keys correlation owns; later milestones add their own keys to `details`.
                    merged = {**(inc.details or {}), **details}
                    merged.pop("stale", None)
                    inc.title, inc.details = c.title[:300], merged
                    rep.incidents_updated += 1
            db.add_all(Correlation(website_id=website_id, incident_id=inc.incident_id if inc else None, event_id=l.event_id,
                                   related_event_id=l.related_event_id, relationship_type=l.relationship_type,
                                   strength=l.strength) for l in c.links)
            rep.correlation_records += len(c.links)
            rep.cluster_summaries.append({
                "cluster_id": c.cluster_id, "incident_id": inc.incident_id if inc else None, "title": c.title,
                "is_potential_incident": c.is_incident_candidate, "event_count": len(c.event_ids),
                "suspicious_event_count": len(c.seed_event_ids), "categories": c.categories,
                "max_finding_confidence": c.max_confidence, "stages": list(c.stages), "link_counts": c.link_counts(),
                "source_ips": c.source_ips, "first_seen": c.first_seen.isoformat(), "last_seen": c.last_seen.isoformat()})
        db.commit()
        return rep
    except Exception as exc:  # noqa: BLE001 - correlation must degrade, not crash callers (PRD failure handling)
        db.rollback()
        log.error("correlation failed for website=%s: %s", website_id, type(exc).__name__)
        return CorrelationReport(status="error", error=f"{type(exc).__name__}")
