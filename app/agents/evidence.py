"""Evidence bundle = the short-term working memory of one investigation (PRD sections 11, 19, 29).

Pure functions over plain dicts (no ORM, no network, no LLM) so the privacy and traceability guarantees are unit-testable.

What the LLM may see (PRD section 11 "raw events must not be sent wholesale to the LLM"; core rules 10-11):
  * counts, stages, rule/model finding summaries, numeric metrics, risk factors, threat-intel *statuses and summaries*;
  * NEVER raw events, request payloads/query strings, source IPs, user ids, session ids, user agents or event bodies.
    Entities are reduced to counts. Strings that remain are control-stripped, character-filtered and truncated.

Every item the model may cite carries a short reference label (F1, S:credential_attack, R:authentication, TI1, T3...).
`refs` maps each label back to concrete event ids / finding ids so every AI claim can be traced to evidence (PRD section 19)
and so claims citing labels that do not exist can be rejected deterministically.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence

# Keys whose string values identify people/hosts/requests. Their values are never forwarded to the LLM.
_SENSITIVE_KEYS = {"source", "sources", "ip", "source_ip", "source_ips", "user", "user_id", "users", "account", "accounts", "target",
                   "targets", "path", "paths", "endpoint", "query", "url", "session", "session_id", "session_ids", "payload",
                   "ua", "user_agent", "referrer", "email", "token", "key", "password"}
_UNSAFE_CHARS = re.compile(r"[^\w\s.,:;/\-@()%+=#]")
# Literal IP addresses inside free text (e.g. an incident title "... from 203.0.113.77", a threat-intel summary) are replaced, never forwarded.
# IPv6 is matched conservatively (8 groups, or a "::" form) so clock times such as 10:31:02 are untouched.
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w])")
_IPV6 = re.compile(r"(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5})?|::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}))(?![\w:])")
IP_PLACEHOLDER = "(source ip)"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SPACE = re.compile(r"\s+")


def safe_text(value: Any, max_len: int = 80) -> str:
    """Control-stripped, character-filtered, truncated text. Removes characters that could break the data delimiters."""
    s = _CONTROL.sub(" ", str(value if value is not None else ""))
    s = _UNSAFE_CHARS.sub("", s)
    s = _IPV6.sub(IP_PLACEHOLDER, _IPV4.sub(IP_PLACEHOLDER, s))
    s = _SPACE.sub(" ", s).strip()
    return s[:max_len]


def safe_metrics(src: Any, max_len: int = 80, *, depth: int = 0) -> dict[str, Any]:
    """Numbers and booleans pass; lists become `<key>_count`; short strings pass unless the key is identifying."""
    out: dict[str, Any] = {}
    if not isinstance(src, Mapping) or depth > 1:
        return out
    for k, v in src.items():
        key = safe_text(k, 40)
        if not key or key.lower() in _SENSITIVE_KEYS:
            continue
        if isinstance(v, bool) or v is None:
            if isinstance(v, bool):
                out[key] = v
        elif isinstance(v, (int, float)):
            out[key] = round(v, 4) if isinstance(v, float) else v
        elif isinstance(v, str):
            t = safe_text(v, max_len)
            if t and IP_PLACEHOLDER not in t and not re.search(r"\d{1,3}(\.\d{1,3}){3}", t):          # a string that carried a literal IP is dropped, not forwarded
                out[key] = t
        elif isinstance(v, (list, tuple, set)):
            out[f"{key}_count"] = len(v)
        elif isinstance(v, Mapping):
            inner = safe_metrics(v, max_len, depth=depth + 1)
            if inner:
                out[key] = inner
    return out


def _iso(v: Any) -> str | None:
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v) if v else None


def _cap(ids: Sequence[str], n: int) -> list[str]:
    return list(dict.fromkeys(ids))[:n]


@dataclass
class EvidenceBundle:
    context: dict[str, Any]                       # what the LLM sees (serialisable)
    refs: dict[str, dict[str, Any]]               # label -> {kind, event_ids, finding_id?, ...} (never sent to the LLM)
    facts: list[dict[str, Any]]                   # deterministic observed facts / derived metrics (never authored by the LLM)
    notes: list[str] = field(default_factory=list)  # truncation / minimisation notes
    truncated: bool = False
    fingerprint: str = ""
    chars: int = 0

    def serialised(self) -> str:
        return json.dumps(self.context, separators=(",", ":"), sort_keys=True, default=str)


def _fact(kind: str, text: str, refs: list[str]) -> dict[str, Any]:
    return {"evidence_type": kind, "text": text, "refs": refs}


def build_bundle(incident: Mapping[str, Any], findings: Sequence[Mapping[str, Any]], timeline: Sequence[Mapping[str, Any]],
                 ti: Mapping[str, Any] | None, risk: Mapping[str, Any] | None, cfg: Mapping[str, Any]) -> EvidenceBundle:
    """incident: {incident_id, title, details{...}}; findings: [{finding_id, agent_name, finding_type, confidence, evidence{...}}]."""
    c = cfg["context"]
    slen = c["string_max_len"]
    ev_cap = c["max_event_ids_per_ref"]
    d = dict(incident.get("details") or {})
    refs: dict[str, dict[str, Any]] = {}
    facts: list[dict[str, Any]] = []
    notes: list[str] = []

    # ---- correlation summary (observed / derived, deterministic)
    stages = {s: int((v or {}).get("event_count") or 0) for s, v in (d.get("stages") or {}).items()}
    for s, v in (d.get("stages") or {}).items():
        ids = [i for i in ((v or {}).get("first_event_id"), (v or {}).get("last_event_id")) if i]
        refs[f"S:{s}"] = {"kind": "stage", "event_ids": _cap(ids, ev_cap), "label": safe_text(s, 60)}
    entities = d.get("entities") or {}
    corr = {
        "event_count": int(d.get("event_count") or 0), "suspicious_event_count": int(d.get("seed_event_count") or 0),
        "stages": {safe_text(s, 60): n for s, n in stages.items()}, "link_counts": safe_metrics(d.get("link_counts") or {}),
        "source_count": len(entities.get("source_ips") or []), "session_count": len(entities.get("session_ids") or []),
        "account_count": len(entities.get("user_ids") or []), "first_seen": _iso(d.get("first_seen")), "last_seen": _iso(d.get("last_seen")),
        "affected_resources": [safe_text(r, slen) for r in (d.get("affected_resources") or [])[:5]],
        "categories": [safe_text(x, 60) for x in (d.get("categories") or [])[:8]],
        "links_truncated": bool(d.get("links_truncated")), "event_ids_truncated": bool(d.get("event_ids_truncated")),
    }
    refs["C:correlation"] = {"kind": "correlation", "event_ids": _cap(list(d.get("event_ids") or [])[:ev_cap], ev_cap)}
    facts.append(_fact("observed", f"{corr['event_count']} correlated events ({corr['suspicious_event_count']} flagged by rules/model) "
                                   f"across {corr['source_count']} source(s), {corr['session_count']} session(s), {corr['account_count']} account(s).", ["C:correlation"]))
    for s, n in stages.items():
        facts.append(_fact("observed", f"Stage '{safe_text(s, 60)}': {n} event(s).", [f"S:{s}"]))

    # ---- findings (rule / model output: derived indicators, not proof)
    ranked = sorted(findings, key=lambda f: (-(float(f.get("confidence") or 0)), str(f.get("finding_id"))))
    fitems: list[dict[str, Any]] = []
    for n, f in enumerate(ranked[: c["max_findings"]], start=1):
        ev = f.get("evidence") or {}
        ref = f"F{n}"
        interp = ev.get("interpretation")
        interp_text = interp.get("text") if isinstance(interp, Mapping) else interp
        fitems.append({"ref": ref, "rule": safe_text(ev.get("rule_id"), 20), "category": safe_text(ev.get("category") or f.get("finding_type"), 60),
                       "type": safe_text(f.get("finding_type"), 40), "source": safe_text(f.get("agent_name"), 30),
                       "confidence": round(float(f.get("confidence") or 0), 3), "title": safe_text(ev.get("rule_title"), slen),
                       "observed": safe_metrics(ev.get("observed"), slen), "metrics": safe_metrics(ev.get("derived_metrics"), slen),
                       "interpretation": safe_text(interp_text, 220)})
        refs[ref] = {"kind": "finding", "finding_id": f.get("finding_id"), "event_ids": _cap([f.get("event_id"), *(ev.get("event_ids") or [])], ev_cap)}
    if len(ranked) > c["max_findings"]:
        notes.append(f"{len(ranked) - c['max_findings']} lower-confidence finding(s) were not sent to the model (context.max_findings).")

    # ---- risk factors (deterministic; the model may not change them)
    risk_ctx: dict[str, Any] | None = None
    if isinstance(risk, Mapping) and risk.get("risk_level"):
        factors = []
        for fv in (risk.get("factors") or []):          # list of dicts, each with a "factor" id (see app/risk/scoring.py)
            fid = safe_text(fv.get("factor"), 40)
            if not fid:
                continue
            factors.append({"ref": f"R:{fid}", "factor": fid, "status": safe_text(fv.get("status"), 30),
                            "weight": fv.get("weight"), "value": fv.get("value"), "points": fv.get("points")})
            refs[f"R:{fid}"] = {"kind": "risk_factor", "event_ids": [], "finding_ids": list(fv.get("finding_ids") or [])[:ev_cap]}
        risk_ctx = {"level": risk["risk_level"], "score": risk.get("risk_score"), "confidence": risk.get("confidence"), "factors": factors,
                    "evidence_gaps": [safe_text((g or {}).get("text") or (g or {}).get("gap") or g, 160) for g in (risk.get("evidence_gaps") or [])[:6]]}
        top = [f["ref"] for f in sorted(factors, key=lambda f: -(f["points"] or 0))[:3]]
        facts.append(_fact("derived_metric", f"Deterministic risk: {risk['risk_level']} (score {risk.get('risk_score')}, evidence confidence {risk.get('confidence')}).", top))

    # ---- threat intelligence (third-party; absence is neither safe nor malicious)
    ti_ctx: dict[str, Any] | None = None
    if isinstance(ti, Mapping) and ti.get("results") is not None:
        items = []
        for n, r in enumerate((ti.get("results") or [])[: c["max_ti_results"]], start=1):
            ref = f"TI{n}"
            items.append({"ref": ref, "type": safe_text(r.get("indicator_type"), 20), "provider": safe_text(r.get("provider"), 30),
                          "status": safe_text(r.get("status"), 20), "evidence_status": safe_text(r.get("evidence_status"), 20),
                          "synthetic": bool(r.get("synthetic")), "summary": safe_text(r.get("summary"), 160)})
            refs[ref] = {"kind": "threat_intel", "event_ids": []}
        ti_ctx = {"status": safe_text(ti.get("status"), 20), "indicators_checked": int(ti.get("indicators_checked") or 0),
                  "contains_synthetic": bool(ti.get("contains_synthetic")), "results": items,
                  "rule": "No evidence from a provider means no evidence was found. It is neither safe nor malicious."}
    else:
        notes.append("Threat-intelligence enrichment was not run for this incident.")

    # ---- timeline (derived presentation of observed events / indicators)
    tl: list[dict[str, Any]] = []
    for n, e in enumerate(list(timeline)[: c["max_timeline_entries"]], start=1):
        ref = f"T{n}"
        tl.append({"ref": ref, "t": _iso(e.get("timestamp")), "type": safe_text(e.get("evidence_type"), 20), "label": safe_text(e.get("label"), 120),
                   "events": int(e.get("event_count") or 0)})
        refs[ref] = {"kind": "timeline", "event_ids": _cap(list(e.get("event_ids") or []), ev_cap), "entry_id": e.get("entry_id")}
    if len(timeline) > c["max_timeline_entries"]:
        notes.append(f"{len(timeline) - c['max_timeline_entries']} timeline entr(ies) were not sent to the model (context.max_timeline_entries).")

    context: dict[str, Any] = {
        "incident": {"id": safe_text(incident.get("incident_id"), 40), "title": safe_text(incident.get("title"), 160),
                     "title_basis": "rule_template (not an AI conclusion)"},
        "correlation": corr, "findings": fitems, "risk": risk_ctx, "threat_intel": ti_ctx, "timeline": tl,
        "known_limitations": [safe_text(x, 200) for x in (d.get("limitations") or [])[:4]],
    }
    bundle = EvidenceBundle(context=context, refs=refs, facts=facts, notes=notes)
    _fit_budget(bundle, int(c["max_chars"]))
    bundle.fingerprint = hashlib.sha256(bundle.serialised().encode()).hexdigest()[:16]
    bundle.chars = len(bundle.serialised())
    return bundle


def _fit_budget(b: EvidenceBundle, max_chars: int) -> None:
    """Deterministically drop the least valuable items until the serialised context fits the budget (free-tier TPM limits are small)."""
    order = [("timeline", 3), ("threat_intel.results", 1), ("findings", 3), ("known_limitations", 0)]
    guard = 0
    while len(b.serialised()) > max_chars and guard < 60:
        guard += 1
        changed = False
        for path, keep in order:
            lst, parent, key = _resolve_list(b.context, path)
            if lst is not None and len(lst) > keep:
                dropped = lst.pop()
                b.refs.pop(dropped.get("ref", ""), None) if isinstance(dropped, dict) else None
                b.truncated = changed = True
                b.notes.append(f"context trimmed to fit max_chars: dropped one item from {path}.")
                break
        if not changed:
            break
    if len(b.serialised()) > max_chars:
        b.notes.append("context still exceeds max_chars after trimming; the model call may fail or be rate limited.")


def _resolve_list(ctx: dict[str, Any], path: str):
    parts = path.split(".")
    node: Any = ctx
    for p in parts[:-1]:
        node = node.get(p) if isinstance(node, dict) else None
        if node is None:
            return None, None, None
    lst = node.get(parts[-1]) if isinstance(node, dict) else None
    return (lst if isinstance(lst, list) else None), node, parts[-1]
