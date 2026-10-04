"""Attack timeline and attack graph (PRD section 18, FR-14/FR-15, AC-12/AC-13, section 19).

Both are DERIVED presentation layers computed from stored events, findings and correlation records; nothing here
is stored and nothing here calls an LLM. Every timeline entry, graph node and graph edge carries the concrete
`event_ids` it rests on (capped for payload size, with the true count alongside) so it can be traced to evidence.

Each item is labelled with an `evidence_type` (PRD section 19):
  observed            directly recorded events (labels contain only recorded facts: counts, types, paths, times)
  derived_indicator   output of the deterministic rules / ML model (a finding), NOT proof of an attack
  system              the platform's own action (the incident being correlated)
AI inference does not exist yet (CrewAI agents arrive in milestone 8) and will be added with its own type.

Labels never include query strings or request bodies: request targets may contain attacker-controlled text, and
the dashboard must still render everything as plain text, never HTML.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from app.correlation.config import CorrelationConfig, get_correlation_config
from app.correlation.engine import STAGE_LABEL, STAGE_ORDER, FindingView, Link, detect_stages

_REL_PRIORITY = ("attack_sequence", "same_session", "same_user", "same_ip", "same_endpoint", "similar_behavior")


def _cap(ids: Sequence[str], n: int) -> tuple[list[str], bool]:
    return list(ids[:n]), len(ids) > n


def _path(e) -> str | None:
    return (e.features or {}).get("path")


def _parse_iso(value: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _duration(a: datetime, b: datetime) -> str:
    s = (b - a).total_seconds()
    return f"{s:.0f} s" if s >= 1 else "<1 s"


def _label(group: Sequence) -> str:
    """Observed-fact label for a run of same-type events."""
    first, n = group[0], len(group)
    t, path = first.event_type, _path(first)
    span = _duration(group[0].timestamp, group[-1].timestamp)
    if t == "login_failure":
        users = len({e.user_id for e in group if e.user_id})
        extra = f", {_plural(users, 'distinct account')}" if users else ""
        return f"{_plural(n, 'failed login attempt')} in {span}{extra}"
    if t == "login_success":
        return f"Successful login{f' for account {first.user_id}' if first.user_id else ''}" + (f" (x{n})" if n > 1 else "")
    if t == "session_created":
        return "New session created" + (f" (x{n})" if n > 1 else "")
    if t == "session_terminated":
        return "Session terminated" + (f" (x{n})" if n > 1 else "")
    if t == "page_view":
        return f"{_plural(n, 'page view')} in {span}"
    if t == "interaction":
        return f"{_plural(n, 'interaction summary event')}"
    where = f": {path}" if path else ""
    name = {"sensitive_endpoint_access": "Sensitive endpoint accessed", "api_access": "API access",
            "http_request": "HTTP request", "waf_alert": "WAF alert reported", "security_decision": "Security control decision recorded",
            "app_error": "Application error"}.get(t, t.replace("_", " ").capitalize())
    status = f" (status {first.status_code})" if first.status_code and t in ("http_request", "app_error", "api_access") else ""
    return (f"{n} \u00d7 " if n > 1 else "") + f"{name}{where}{status}"


def group_events(events: Sequence, gap_s: float) -> list[list]:
    """Consecutive (time-sorted) events with the same type, session and source IP, closer than `gap_s`, form one group."""
    groups: list[list] = []
    for e in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        g = groups[-1] if groups else None
        if g and (g[-1].event_type, g[-1].session_id, g[-1].source_ip) == (e.event_type, e.session_id, e.source_ip) \
                and (e.timestamp - g[-1].timestamp).total_seconds() <= gap_s:
            g.append(e)
        else:
            groups.append([e])
    return groups


def build_timeline(events: Sequence, findings: Sequence[FindingView], *, incident_created_at: datetime | None = None,
                   cfg: CorrelationConfig | None = None, enrichment: dict[str, Any] | None = None,
                   investigation: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    cfg = cfg or get_correlation_config()
    cap = cfg["timeline"]["max_event_ids_per_entry"]
    by_id = {e.event_id: e for e in events}
    stage_of_event = {i: s for s, ids in detect_stages(events, findings).items() for i in ids}
    entries: list[dict[str, Any]] = []

    for g in group_events(events, cfg["timeline"]["group_gap_s"]):
        ids, trunc = _cap([e.event_id for e in g], cap)
        stages = sorted({stage_of_event[e.event_id] for e in g if e.event_id in stage_of_event}, key=STAGE_ORDER.index)
        entries.append({
            "kind": "observed", "evidence_type": "observed", "timestamp": g[0].timestamp, "end_timestamp": g[-1].timestamp,
            "label": _label(g), "event_type": g[0].event_type, "event_count": len(g),
            "session_ids": sorted({e.session_id for e in g if e.session_id}), "source_ips": sorted({e.source_ip for e in g if e.source_ip}),
            "stages": stages, "event_ids": ids, "event_ids_truncated": trunc, "_order": 0})

    for f in sorted(findings, key=lambda f: (by_id[f.event_id].timestamp if f.event_id in by_id else datetime.max, f.finding_id)):
        if f.event_id not in by_id:
            continue
        cited = [i for i in dict.fromkeys([f.event_id, *f.event_ids]) if i in by_id]
        ids, trunc = _cap(cited, cap)
        entries.append({
            "kind": "detection", "evidence_type": "derived_indicator", "timestamp": by_id[f.event_id].timestamp, "end_timestamp": None,
            "label": f"Detection {f.rule_id or f.finding_type}: {f.title}", "finding_id": f.finding_id, "agent_name": f.agent_name,
            "category": f.category, "confidence": f.confidence, "event_count": len(cited), "event_ids": ids,
            "event_ids_truncated": trunc,
            "note": "Rule/model output; confidence is a configured weight, not a probability, and the indicator is not proof.", "_order": 1})

    entries.sort(key=lambda x: (x["timestamp"], x["_order"], x.get("finding_id") or "", x["label"]))
    if incident_created_at is not None:
        entries.append({"kind": "system", "evidence_type": "system", "timestamp": incident_created_at, "end_timestamp": None,
                        "label": "Incident correlated", "event_count": 0, "event_ids": [], "event_ids_truncated": False, "_order": 2})
    enriched_at = _parse_iso((enrichment or {}).get("retrieved_at"))
    if enriched_at is not None:   # PRD section 18 timeline step "Threat intelligence enrichment" (platform action, not an observation)
        n_ind = int(enrichment.get("indicators_checked") or 0)
        synth = " (includes SYNTHETIC demo data)" if enrichment.get("contains_synthetic") else ""
        entries.append({"kind": "system", "evidence_type": "system", "timestamp": enriched_at, "end_timestamp": None,
                        "label": f"Threat intelligence enrichment: {_plural(n_ind, 'indicator')} checked{synth}", "event_count": 0,
                        "event_ids": [], "event_ids_truncated": False, "_order": 3})
    inv_at = _parse_iso((investigation or {}).get("generated_at")) if (investigation or {}).get("status") == "ok" else None
    if inv_at is not None:   # M8: an AI step is labelled as inference, never as an observation (PRD section 19)
        hyp = (((investigation or {}).get("inference") or {}).get("hypothesis")) or {}
        ids, trunc = _cap(list(hyp.get("event_ids") or []), cap)
        entries.append({"kind": "ai_inference", "evidence_type": "ai_inference", "timestamp": inv_at, "end_timestamp": None,
                        "label": "AI investigation: hypothesis generated (inference grounded in cited evidence; not proof)", "event_count": len(ids),
                        "event_ids": ids, "event_ids_truncated": trunc, "model": (investigation or {}).get("model"), "_order": 4})
    for n, e in enumerate(entries, start=1):
        e.pop("_order")
        e["entry_id"] = f"tl_{n:03d}"
    return entries


def _best_relationship(links_by_pair: dict[tuple[str, str], list[Link]], a_ids: Sequence[str], b_ids: Sequence[str]) -> tuple[str, float] | None:
    # Chain links join temporally adjacent events, so only the boundary events of two adjacent groups can be linked;
    # looking at the last/first 25 keeps this bounded for very large groups.
    best: tuple[int, float, str] | None = None
    bs = list(b_ids[:25])
    for x in a_ids[-25:]:
        for y in bs:
            for l in links_by_pair.get((x, y), ()):
                cand = (_REL_PRIORITY.index(l.relationship_type), -l.strength, l.relationship_type)
                if best is None or cand < best:
                    best = cand
    return (best[2], -best[1]) if best else None


def build_graph(events: Sequence, findings: Sequence[FindingView], links: Sequence[Link], *, incident_id: str,
                title: str, cfg: CorrelationConfig | None = None) -> dict[str, Any]:
    """Nodes: source IPs, sessions, event groups (one per timeline group), the incident.
    Edges: ip->session, session->first group, group->next group (time order, labelled with the strongest stored
    correlation between the two groups, else `temporal`), finding-bearing group->incident."""
    cfg = cfg or get_correlation_config()
    cap = cfg["timeline"]["max_event_ids_per_entry"]
    by_id = {e.event_id: e for e in events}
    stage_of_event = {i: s for s, ids in detect_stages(events, findings).items() for i in ids}
    flagged = defaultdict(list)
    for f in findings:
        for i in dict.fromkeys([f.event_id, *f.event_ids]):
            if i in by_id:
                flagged[i].append(f)
    links_by_pair: dict[tuple[str, str], list[Link]] = defaultdict(list)
    for l in links:
        links_by_pair[(l.event_id, l.related_event_id)].append(l)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def node(nid: str, ntype: str, label: str, ids: Sequence[str], layer: int, **extra: Any) -> None:
        c, trunc = _cap(list(ids), cap)
        nodes.append({"id": nid, "type": ntype, "label": label, "event_count": len(ids), "event_ids": c,
                      "event_ids_truncated": trunc, "layer": layer, **extra})

    def edge(src: str, dst: str, rel: str, ids: Sequence[str], evidence_type: str, *, strength: float | None = None,
             correlation_type: str | None = None) -> None:
        c, trunc = _cap(list(ids), cap)
        edges.append({"id": f"e{len(edges) + 1:03d}", "source": src, "target": dst, "relationship": rel,
                      "correlation_type": correlation_type, "strength": strength, "evidence_type": evidence_type,
                      "event_ids": c, "event_ids_truncated": trunc})

    groups = group_events(events, cfg["timeline"]["group_gap_s"])
    gnodes = []                                   # (node id, events, event ids, finding ids, stages, layer)
    for n, g in enumerate(groups, start=1):
        ids = [e.event_id for e in g]
        stages = sorted({stage_of_event[i] for i in ids if i in stage_of_event}, key=STAGE_ORDER.index)
        fl = sorted({f.finding_id for i in ids for f in flagged.get(i, [])})
        gnodes.append((f"g{n:03d}", g, ids, fl, stages, 1 + n))

    ips = sorted({e.source_ip for e in events if e.source_ip})
    sessions = sorted({e.session_id for e in events if e.session_id})
    for ip in ips:
        node(f"ip:{ip}", "source_ip", ip, [e.event_id for e in events if e.source_ip == ip], 0)
    for sid in sessions:
        node(f"sess:{sid}", "session", sid, [e.event_id for e in events if e.session_id == sid], 1)
    for gid, g, ids, fl, stages, layer in gnodes:
        node(gid, "event_group", _label(g), ids, layer, stages=stages, stage_labels=[STAGE_LABEL[s] for s in stages],
             finding_ids=fl, evidence_type="observed", timestamp=g[0].timestamp, end_timestamp=g[-1].timestamp)
    last_layer = max((n["layer"] for n in nodes), default=1) + 1
    node(f"inc:{incident_id}", "incident", title, [e.event_id for e in events], last_layer, evidence_type="system")

    seen_ip_sess: set[tuple[str, str]] = set()
    for e in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        if e.source_ip and e.session_id and (e.source_ip, e.session_id) not in seen_ip_sess:
            seen_ip_sess.add((e.source_ip, e.session_id))
            ids = [x.event_id for x in events if x.source_ip == e.source_ip and x.session_id == e.session_id]
            edge(f"ip:{e.source_ip}", f"sess:{e.session_id}", "used_session", ids, "observed")

    anchored: set[str] = set()                     # sessions / IPs that already have a first group
    for gid, g, ids, _fl, _st, _ly in gnodes:
        sid, ip = g[0].session_id, g[0].source_ip
        if sid and sid not in anchored:
            anchored.add(sid)
            edge(f"sess:{sid}", gid, "began_with", ids, "observed")
        elif not sid and ip and f"ip:{ip}" not in anchored:   # session-less events hang off the source IP
            anchored.add(f"ip:{ip}")
            edge(f"ip:{ip}", gid, "began_with", ids, "observed")

    for (gid_a, _ga, ids_a, *_), (gid_b, _gb, ids_b, *_) in zip(gnodes, gnodes[1:]):
        rel = _best_relationship(links_by_pair, ids_a, ids_b)
        edge(gid_a, gid_b, "followed_by", [*ids_a[-1:], *ids_b[:1]],
             "derived_correlation" if rel else "observed",
             strength=rel[1] if rel else None, correlation_type=rel[0] if rel else "temporal")

    for gid, _g, ids, fl, *_ in gnodes:
        if fl:
            edge(gid, f"inc:{incident_id}", "evidence_for", ids, "derived_indicator")
    return {"incident_id": incident_id, "nodes": nodes, "edges": edges,
            "node_count": len(nodes), "edge_count": len(edges),
            "note": "Derived from stored events and correlation records; every node/edge lists the event ids it rests on. "
                    "Node labels are recorded facts only; indicators are rule/model output, not proof."}
