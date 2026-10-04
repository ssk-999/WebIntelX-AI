"""Sessionisation (PRD section 11, FR-09: 'create/maintain session context from events').

PRD has no sessions table, so session context is DERIVED from stored events on demand (single source of
truth = events; nothing to keep in sync). Grouping key = `session_id`; events without one fall back to
`ip:<source_ip>` (flagged `inferred=True`), else `unknown`.

Linking a pre-login session to the post-login session (e.g. sess-h-pre -> sess-h-auth) is NOT done here:
that is event correlation (milestone 5), based on shared IP/user, and must stay a separate, explainable step.
"""
from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Protocol, Sequence


class EventLike(Protocol):  # the ORM Event satisfies this; tests can use simple stand-ins
    event_id: str
    timestamp: datetime
    source_ip: str | None
    user_id: str | None
    session_id: str | None
    event_type: str
    features: dict | None


def session_key(e: EventLike) -> tuple[str, bool]:
    if e.session_id:
        return e.session_id, False
    if e.source_ip:
        return f"ip:{e.source_ip}", True
    return "unknown", True


def peak_in_window(times: Sequence[float], window_s: float) -> tuple[int, int]:
    """Largest number of points inside any window of `window_s` seconds (two-pointer, `times` sorted).
    Returns (count, index_of_last_point_in_that_window); (0, -1) for empty input."""
    best, best_end, lo = 0, -1, 0
    for hi, t in enumerate(times):
        while t - times[lo] > window_s:
            lo += 1
        if hi - lo + 1 > best:
            best, best_end = hi - lo + 1, hi
    return best, best_end


@dataclass
class SessionContext:
    key: str
    inferred: bool
    first_seen: datetime
    last_seen: datetime
    duration_s: float
    event_count: int
    source_ips: list[str]
    user_ids: list[str]
    event_types: dict[str, int]
    page_views: int
    interaction_events: int
    interaction_total: int
    request_events: int
    distinct_paths: int
    login_failures: int
    login_successes: int
    distinct_failed_users: int
    sensitive_accesses: int
    error_events: int
    waf_alerts: int
    ua_classes: list[str]
    webdriver_seen: bool
    median_page_gap_s: float | None
    peak_requests_10s: int
    requests_per_min: float | None
    event_ids: list[str] = field(default_factory=list, repr=False)

    def to_dict(self, include_event_ids: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not include_event_ids:
            d.pop("event_ids")
        d["first_seen"], d["last_seen"] = self.first_seen.isoformat(), self.last_seen.isoformat()
        return d


def _summarise(key: str, inferred: bool, evs: list[EventLike]) -> SessionContext:
    evs = sorted(evs, key=lambda e: (e.timestamp, e.event_id))
    feats = [e.features or {} for e in evs]
    first, last = evs[0].timestamp, evs[-1].timestamp
    duration = (last - first).total_seconds()

    req_times = [e.timestamp.timestamp() for e, f in zip(evs, feats) if f.get("is_request_event")]
    pv_times = [e.timestamp.timestamp() for e in evs if e.event_type == "page_view"]
    gaps = [b - a for a, b in zip(pv_times, pv_times[1:])]
    types = Counter(e.event_type for e in evs)
    peak, _ = peak_in_window(req_times, 10.0)
    req_span = (req_times[-1] - req_times[0]) if len(req_times) > 1 else 0.0

    return SessionContext(
        key=key,
        inferred=inferred,
        first_seen=first,
        last_seen=last,
        duration_s=round(duration, 3),
        event_count=len(evs),
        source_ips=sorted({e.source_ip for e in evs if e.source_ip}),
        user_ids=sorted({e.user_id for e in evs if e.user_id}),
        event_types=dict(sorted(types.items())),
        page_views=types.get("page_view", 0),
        interaction_events=types.get("interaction", 0),
        interaction_total=sum(f.get("interaction_total") or 0 for f in feats),
        request_events=len(req_times),
        distinct_paths=len({f.get("path") for f in feats if f.get("is_request_event") and f.get("path")}),
        login_failures=types.get("login_failure", 0),
        login_successes=types.get("login_success", 0),
        distinct_failed_users=len({e.user_id for e in evs if e.event_type == "login_failure" and e.user_id}),
        sensitive_accesses=sum(1 for f in feats if f.get("is_sensitive_endpoint")),
        error_events=sum(1 for f in feats if f.get("is_error_status")),
        waf_alerts=types.get("waf_alert", 0),
        ua_classes=sorted({f["ua_class"] for f in feats if f.get("ua_class")}),
        webdriver_seen=any(f.get("webdriver") is True for f in feats),
        median_page_gap_s=round(statistics.median(gaps), 3) if gaps else None,
        peak_requests_10s=peak,
        requests_per_min=round(len(req_times) / req_span * 60, 2) if req_span >= 1 else None,
        event_ids=[e.event_id for e in evs],
    )


def sessionize(events: Iterable[EventLike]) -> dict[str, SessionContext]:
    groups: dict[str, list[EventLike]] = {}
    inferred: dict[str, bool] = {}
    for e in events:
        k, inf = session_key(e)
        groups.setdefault(k, []).append(e)
        inferred[k] = inf
    return {k: _summarise(k, inferred[k], v) for k, v in groups.items()}
