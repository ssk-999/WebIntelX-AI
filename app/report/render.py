"""Markdown / HTML renderers for the structured incident report (FR-24).

Both renderers consume the dict from `builder.build_report`, go through ONE neutral block list, and treat EVERY dynamic value as untrusted text
(request paths, third-party threat-intel summaries, AI text and analyst comments can contain attacker-controlled characters):
  * Markdown: control characters stripped, HTML special characters entity-escaped, Markdown specials backslash-escaped, newlines collapsed.
  * HTML: `html.escape` on every value; static markup and inline CSS only; no script, no remote resources; served with a restrictive CSP.
"""
from __future__ import annotations

import html
import re
from typing import Any, Mapping

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# `_` is only escaped at a word boundary: intra-word underscores (incident ids such as inc_ab12) never start emphasis, and escaping them hurts copy/paste.
_MD_SPECIAL = re.compile(r"([\\`*\[\]|~#!]|(?<![A-Za-z0-9])_|_(?![A-Za-z0-9]))")
_SPACE = re.compile(r"\s+")


def _clean(v: Any, max_len: int = 600) -> str:
    s = _SPACE.sub(" ", _CONTROL.sub(" ", "" if v is None else str(v))).strip()
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def md_text(v: Any, max_len: int = 600) -> str:
    return _MD_SPECIAL.sub(r"\\\1", html.escape(_clean(v, max_len), quote=False))


def _fmt(v: Any) -> str:
    if v is None or v == "":
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ", ".join(_clean(x, 80) for x in v) or "—"
    return _clean(v)


def _num(v: Any) -> str:
    return "—" if v is None else (f"{v:g}" if isinstance(v, (int, float)) and not isinstance(v, bool) else _clean(v, 40))


# ------------------------------------------------------------------------------------------------------------------ blocks
def blocks(r: Mapping[str, Any]) -> list[tuple]:
    b: list[tuple] = []
    hyp, risk, ti, rec = r["attack_hypothesis"], r["risk"], r["threat_intelligence"], r["recommended_response"]
    lim, an, ev, g = r["evidence_limitations"], r["analyst_decision"], r["supporting_evidence"], r["attack_graph_summary"]
    b += [("h1", f"Incident report {r['incident_id']}"), ("p", r["title"]), ("p", r["executive_summary"])]
    if r.get("contains_synthetic_data"):
        b.append(("p", "NOTE: this incident contains SYNTHETIC DEMO DATA (controlled sample data, not real traffic)."))
    d, s = r["detection_time"], r["source_information"]
    b += [("h2", "Incident"), ("kv", [("Incident ID", r["incident_id"]), ("Status", r["status"]), ("Report generated", r["generated_at"]), ("Detected (incident created)", d["incident_created_at"]),
                                      ("First seen", d["first_seen"]), ("Last seen", d["last_seen"]), ("Affected resources", r["affected_resources"])]),
          ("h2", "Source information"), ("kv", [("Source IPs", s["source_ips"]), ("Sessions", s["session_count"]), ("Accounts", s["account_count"]), ("Correlated events", s["event_count"])]),
          ("p", s["note"])]
    b.append(("h2", "Attack hypothesis (AI inference, not proof)"))
    if hyp["available"]:
        b += [("p", hyp["statement"]), ("kv", [("Category (AI)", hyp["attack_category"]), ("Confidence", _num(hyp["confidence"])), ("Confidence basis", hyp["confidence_basis"]),
                                                ("Evidence refs", hyp["refs"]), ("Model", hyp["model"]), ("Generated", hyp["generated_at"])])]
        if hyp["alternative_explanations"]:
            b += [("p", "Alternative explanations the AI considered:"), ("ul", hyp["alternative_explanations"])]
        if hyp["stale"]:
            b.append(("p", "WARNING: this hypothesis may be out of date: " + "; ".join(hyp["stale_reasons"])))
    else:
        b.append(("p", hyp["note"]))
    t = r["timeline"]
    b += [("h2", "Timeline"), ("p", t["note"]),
          ("table", ["Time (UTC)", "Evidence type", "Entry", "Events", "Event ids"],
           [[e["timestamp"], e["evidence_type"], e["label"], e["event_count"], e["event_ids"]] for e in t["entries"]])]
    if t["truncated"]:
        b.append(("p", f"Showing the first {len(t['entries'])} of {t['entry_count']} entries."))
    b += [("h2", "Attack graph summary"), ("kv", [("Nodes", g["node_count"]), ("Edges", g["edge_count"]), ("Nodes by type", ", ".join(f"{k}: {v}" for k, v in g["nodes_by_type"].items())),
                                                  ("Edges by relationship", ", ".join(f"{k}: {v}" for k, v in g["edges_by_relationship"].items())), ("Layered path", " → ".join(g["layered_path"]))]),
          ("p", g["traceability"])]
    b += [("h2", "Supporting evidence"), ("h3", "Observed facts and derived metrics (code-authored)"),
          ("table", ["Type", "Statement", "Refs"], [[f["evidence_type"], f["text"], f["refs"]] for f in ev["facts"]]),
          ("h3", "Supporting findings (rules / ML model; indicators, not proof)"),
          ("table", ["Finding", "Source", "Category", "Rule", "Confidence"], [[f["finding_id"], f["agent_name"], f["category"], f["rule_id"], _num(f["confidence"])] for f in ev["supporting_findings"]]),
          ("h3", "AI supporting claims (AI inference)"),
          ("table", ["Claim", "Refs", "Event ids"], [[c["claim"], c["refs"], c["event_ids"]] for c in ev["ai_supporting_claims"]])]
    b += [("h2", "Threat intelligence"), ("kv", [("Status", ti["status"]), ("Indicators checked", ti.get("indicators_checked")), ("Synthetic data included", ti.get("contains_synthetic_data", False))]),
          ("table", ["Indicator", "Type", "Provider", "Status", "Evidence", "Summary"],
           [[x["indicator"], x["indicator_type"], x["provider"], x["status"], x["evidence_status"], x["summary"]] for x in ti["results"]]), ("ul", ti["notes"])]
    m = r["mitre_attack"]
    b += [("h2", "MITRE ATT&CK mapping (context, not proof)"), ("table", ["Technique", "Name", "Tactics"], [[x["technique_id"], x["name"], x["tactics"]] for x in m["techniques"]]), ("p", m["note"])]
    b += [("h2", "Risk and confidence"), ("kv", [("Risk level", risk["risk_level"]), ("Risk score (0-100)", _num(risk["risk_score"])), ("Confidence (evidence quality)", _num(risk["confidence"])),
                                                  ("Scoring configuration", risk.get("config_fingerprint"))]),
          ("table", ["Factor", "Status", "Weight", "Value", "Points", "Basis"], [[f["label"] or f["factor"], f["status"], _num(f["weight"]), _num(f["value"]), _num(f["points"]), f["basis"]] for f in risk["factors"]]),
          ("p", risk["note"])]
    b.append(("h2", "Recommended response (proposals; human approval required)"))
    if rec["recommendations"]:
        b.append(("table", ["Priority", "Action", "Rationale", "Limitations", "Analyst decision"],
                  [[x["priority"], f"{x['title']} ({x['action']})", x["rationale"], x["limitations"],
                    (x["analyst_decision"] or {}).get("decision") or "none yet"] for x in rec["recommendations"]]))
        b.append(("p", rec["approval_note"]))
    else:
        b.append(("p", rec["note"]))
    b += [("h2", "Evidence limitations"), ("h3", "Correlation limitations"), ("ul", lim["correlation_limitations"]),
          ("h3", "Deterministic evidence gaps"), ("ul", [f"{x['text']}" for x in lim["deterministic_evidence_gaps"]]),
          ("h3", "Missing evidence identified by the AI"), ("ul", [f"{x['description']} — {x['why_it_matters']}" if x["why_it_matters"] else x["description"] for x in lim["ai_missing_evidence"]]),
          ("ul", lim["context_notes"])]
    b += [("h2", "Analyst decision"), ("kv", [("Current status", an["status"]), ("Decision", an["decision"]), ("Comment", an["comment"]), ("Decided at", an["decided_at"])]), ("p", an["note"]),
          ("table", ["Time", "From", "To", "By", "Reason", "Comment"], [[h["at"], h["from"], h["to"], h["actor"], h["reason"], h["comment"]] for h in an["status_history"]])]
    a = r["audit_trail"]
    b += [("h2", "Audit trail"), ("table", ["Time", "Action", "Actor", "Detail"],
                                  [[e["at"], e["action"], e["actor"], " ".join(f"{k}={_fmt(e[k])}" for k in ("decision", "from", "to", "recommended_action", "executed") if e.get(k) not in (None, ""))] for e in a["entries"]]),
          ("p", a["note"]), ("h2", "Disclaimers"), ("ul", r["disclaimers"])]
    return b


# ------------------------------------------------------------------------------------------------------------------ Markdown
def to_markdown(report: Mapping[str, Any]) -> str:
    out: list[str] = []
    for blk in blocks(report):
        kind = blk[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"{'#' * int(kind[1])} {md_text(blk[1], 200)}\n")
        elif kind == "p":
            out.append(md_text(blk[1], 1200) + "\n")
        elif kind == "kv":
            out.append("\n".join(f"- **{md_text(k, 80)}:** {md_text(_fmt(v))}" for k, v in blk[1]) + "\n")
        elif kind == "ul":
            if blk[1]:
                out.append("\n".join(f"- {md_text(x)}" for x in blk[1]) + "\n")
        elif kind == "table":
            if not blk[2]:
                out.append("_None._\n")
                continue
            out.append("| " + " | ".join(md_text(h, 60) for h in blk[1]) + " |\n|" + "---|" * len(blk[1]) + "\n"
                       + "\n".join("| " + " | ".join(md_text(_fmt(c), 300) for c in row) + " |" for row in blk[2]) + "\n")
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------------------------ HTML
_CSS = ("body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1b1f23;line-height:1.45}"
        "h1{font-size:1.6rem}h2{border-bottom:1px solid #d0d7de;padding-bottom:.2rem;margin-top:2rem}"
        "table{border-collapse:collapse;width:100%;font-size:.85rem;margin:.5rem 0}td,th{border:1px solid #d0d7de;padding:.3rem .5rem;text-align:left;vertical-align:top;word-break:break-word}"
        "th{background:#f6f8fa}dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{font-weight:600}dd{margin:0;word-break:break-word}")
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def _h(v: Any, max_len: int = 600) -> str:
    return html.escape(_clean(v, max_len), quote=True)


def to_html(report: Mapping[str, Any]) -> str:
    out: list[str] = []
    for blk in blocks(report):
        kind = blk[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"<{kind}>{_h(blk[1], 200)}</{kind}>")
        elif kind == "p":
            out.append(f"<p>{_h(blk[1], 1200)}</p>")
        elif kind == "kv":
            out.append("<dl>" + "".join(f"<dt>{_h(k, 80)}</dt><dd>{_h(_fmt(v))}</dd>" for k, v in blk[1]) + "</dl>")
        elif kind == "ul":
            if blk[1]:
                out.append("<ul>" + "".join(f"<li>{_h(x)}</li>" for x in blk[1]) + "</ul>")
        elif kind == "table":
            if not blk[2]:
                out.append("<p><em>None.</em></p>")
                continue
            out.append("<table><thead><tr>" + "".join(f"<th>{_h(x, 60)}</th>" for x in blk[1]) + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{_h(_fmt(c), 300)}</td>" for c in row) + "</tr>" for row in blk[2]) + "</tbody></table>")
    title = _h(f"Incident report {report['incident_id']}", 120)
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"{html.escape(CSP)}\">"
            f"<title>{title}</title><style>{_CSS}</style></head><body>{''.join(out)}</body></html>")
