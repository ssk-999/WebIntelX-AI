"""WebIntelX AI Security Dashboard (PRD section 23). Run:  streamlit run dashboard/streamlit_app.py

Thin UI over the FastAPI backend. All shaping/escaping lives in dashboard/viewmodels.py (unit-tested). Untrusted text
(finding labels, request targets, third-party summaries) always goes through `md_escape` before st.markdown.
Milestone 10 Part 2: the Analyst actions tab (decision + comment, accept/reject/further-investigate per recommendation, lifecycle steps, history)
and the Report tab (Markdown / HTML / JSON download) call the M10 Part 1 endpoints. Nothing in the UI executes a response action.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so `streamlit run dashboard/streamlit_app.py` finds the package

import plotly.graph_objects as go
import streamlit as st

from dashboard import embedded_backend
from dashboard import viewmodels as vm
from dashboard.api_client import ApiClient, ApiError

st.set_page_config(page_title="WebIntelX AI", page_icon="🛡️", layout="wide")


def _secret(name: str):
    try:
        return st.secrets[name]
    except Exception:  # noqa: BLE001 - no secrets file / key is fine
        return None


def _embedded_enabled() -> bool:
    return embedded_backend.is_truthy(os.environ.get("WEBINTELX_EMBEDDED_BACKEND") or _secret("WEBINTELX_EMBEDDED_BACKEND"))


def _bootstrap_backend() -> str | None:
    """Optional single-process mode (README 'Deploy'): start the FastAPI backend inside this Streamlit process. Returns an error text or None."""
    if not _embedded_enabled():
        return None
    try:
        embedded_backend.bridge_secrets(st.secrets, os.environ)       # secrets -> env BEFORE the backend reads its settings
    except Exception:  # noqa: BLE001 - no secrets file is fine
        pass
    res = embedded_backend.ensure_started(embedded_backend.port_from(os.environ))
    return None if res["status"] in ("running", "already_running", "started") else res["message"]


def _backend_url() -> str:
    if _embedded_enabled():
        return embedded_backend.local_url(embedded_backend.port_from(os.environ))
    return _secret("WEBINTELX_API_URL") or os.environ.get("WEBINTELX_API_URL", "http://127.0.0.1:8000")


def client() -> ApiClient:
    if "client" not in st.session_state:
        st.session_state.client = ApiClient(_backend_url())
    return st.session_state.client


def show_error(exc: ApiError) -> None:
    if exc.kind == "unauthorized":
        st.session_state.pop("client", None)
        st.session_state.pop("website_id", None)
    st.error(vm.error_banner(exc.kind if exc.kind in ("backend_down", "unauthorized", "database") else "", exc.message))


def md(text) -> None:
    st.markdown(vm.md_escape(text))


def _flash(kind: str, text: str) -> None:
    """Message that survives the st.rerun() that follows a successful analyst action."""
    st.session_state.flash = (kind, text)


def _show_flash() -> None:
    f = st.session_state.pop("flash", None)
    if f:
        {"success": st.success, "warning": st.warning, "info": st.info}.get(f[0], st.info)(f[1])


def _do_action(fn, success_text: str) -> None:
    """Run ONE analyst action against the backend. Success -> flash + rerun (fresh data). Refusal (409 / 422) -> the backend's message, nothing changed.
    The backend only records human decisions; no response action is ever executed."""
    try:
        fn()
    except ApiError as e:
        if e.kind == "unauthorized":
            show_error(e)
            return
        (st.error if e.kind in ("backend_down", "database") else st.warning)(vm.action_error_text(e.kind, e.message, e.code))
        return
    for k in [k for k in st.session_state.keys() if str(k).startswith("report_")]:       # a cached report would now be stale
        st.session_state.pop(k, None)
    _flash("success", success_text)
    st.rerun()


def badge(level: str) -> str:
    return f":{ {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'blue', 'LOW': 'green'}.get(level, 'gray') }[**{level}**]"


# ----------------------------------------------------------------------------------------------- auth
def auth_page() -> None:
    st.title("🛡️ WebIntelX AI")
    st.caption("From suspicious visitor behavior to an explainable attack story.")
    tab_in, tab_up = st.tabs(["Sign in", "Create account"])
    with tab_in:
        with st.form("login"):
            email, pw = st.text_input("Email"), st.text_input("Password", type="password")
            if st.form_submit_button("Sign in"):
                try:
                    client().login(email, pw)
                    st.session_state.email = email
                    st.rerun()
                except ApiError as e:
                    show_error(e)
    with tab_up:
        with st.form("register"):
            email, pw = st.text_input("Email", key="r_email"), st.text_input("Password (min 8 characters)", type="password", key="r_pw")
            if st.form_submit_button("Create account"):
                try:
                    client().register(email, pw)
                    client().login(email, pw)
                    st.session_state.email = email
                    st.rerun()
                except ApiError as e:
                    show_error(e)


# ----------------------------------------------------------------------------------------------- onboarding
def onboarding_page(sites: list[dict]) -> None:
    st.header("Onboarding")
    st.subheader("1. Register a website")
    with st.form("new_site"):
        domain = st.text_input("Website domain", placeholder="demo.example.com")
        if st.form_submit_button("Register website"):
            try:
                res = client().create_website(domain)
                st.session_state.website_id = res["website"]["website_id"]
                st.session_state.new_key = {"key": res["ingestion_key"], "snippet": res["sdk_snippet"]}
                st.session_state.goto_page = "Onboarding"      # the key is shown once, on this page
                st.rerun()
            except ApiError as e:
                show_error(e)
    nk = st.session_state.get("new_key")
    if nk:
        st.success("Website registered. The ingestion key is a limited-scope identifier and is shown only once.")
        st.code(nk["key"])
        st.markdown("**2. Install the SDK:** paste before `</head>` on every monitored page.")
        st.code(nk["snippet"], language="html")
    if not sites:
        return
    site = _pick_site(sites)
    st.subheader("Credentials")
    try:
        creds = client().credentials(site["website_id"])
        st.dataframe([{k: c.get(k) for k in ("credential_id", "key_prefix", "status", "created_at", "rotated_at", "revoked_at")} for c in creds])
        c1, c2 = st.columns(2)
        if c1.button("Rotate credential (old key stops working immediately)"):
            res = client().rotate_credential(site["website_id"])
            st.session_state.new_key = {"key": res["ingestion_key"], "snippet": res["sdk_snippet"]}
            st.session_state.goto_page = "Onboarding"
            st.rerun()
        active = [c for c in creds if c.get("status") == "active"]
        if active and c2.button("Revoke active credential"):
            client().revoke_credential(site["website_id"], active[0]["credential_id"])
            st.rerun()
        st.subheader("3. Verify installation")
        if st.button("Verify installation"):
            v = client().verification(site["website_id"])
            (st.success if v["status"] == "active" else st.warning)(
                f"Telemetry {v['status'].replace('_', ' ')} - {v['events_received']} event(s) received.")
        with st.expander("Load controlled SYNTHETIC demo data (no real customer data)"):
            st.caption("Loads the hero credential-abuse scenario, runs detection, correlation and risk scoring. Events are flagged synthetic.")
            if st.button("Load hero scenario"):
                with st.spinner("Loading synthetic scenario..."):
                    res = client().load_demo(site["website_id"])
                st.success(f"Loaded {res.get('loaded', 0)} synthetic events ({res.get('rejected', 0)} rejected). Open the Dashboard.")
    except ApiError as e:
        show_error(e)


def _pick_site(sites: list[dict]) -> dict:
    ids = [s["website_id"] for s in sites]
    cur = st.session_state.get("website_id")
    idx = ids.index(cur) if cur in ids else 0
    site = st.sidebar.selectbox("Website", sites, index=idx, format_func=lambda s: s["domain"])
    st.session_state.website_id = site["website_id"]
    return site


def _open_incident(incident_id: str) -> None:
    """Button callback: callbacks run before widgets are created, so setting the sidebar radio's key here is allowed."""
    st.session_state.incident_id = incident_id
    st.session_state.page = "Incident investigation"


# ----------------------------------------------------------------------------------------------- dashboard
def dashboard_page(site: dict) -> None:
    st.header(f"Security Dashboard - {vm.md_escape(site['domain'])}")
    wid = site["website_id"]
    c = client()
    try:
        verification, incidents = c.verification(wid), c.incidents(wid)
        alerts = c.alerts(wid).get("alerts", [])
        findings = c.findings(wid, limit=500)
        events = c.events(wid, limit=15)
        sessions = c.sessions(wid)
    except ApiError as e:
        show_error(e)
        return
    k = vm.dashboard_kpis(verification, findings, incidents, alerts, findings_limit=500)
    cols = st.columns(5)
    cols[0].metric("Monitoring", k["monitoring_status"].replace("_", " "))
    cols[1].metric("Total events", k["total_events"])
    cols[2].metric("Suspicious events", f"{'≥' if k['suspicious_events_is_lower_bound'] else ''}{k['suspicious_events']}")
    cols[3].metric("Active incidents", k["active_incidents"])
    cols[4].metric("High-risk incidents", k["high_risk_incidents"])
    st.caption("Counts are measured from this website's stored data. They are not production performance claims.")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Active incidents")
        cards = vm.incident_cards(incidents, alerts)
        if not cards:
            st.info("No incidents yet. Load the synthetic demo scenario from Onboarding, or send telemetry with the SDK.")
        for card in cards:
            with st.container(border=True):
                st.markdown(f"{badge(card['risk_level'])} &nbsp; {vm.md_escape(card['title'])}")
                score = "not scored" if card["risk_score"] is None else f"{card['risk_score']:.1f}"
                conf = "n/a" if card["confidence"] is None else f"{card['confidence']:.2f}"
                st.caption(f"Risk score {score} · evidence confidence {conf} · status {card['status']} · {card['event_count'] or '?'} events"
                           + (f" · alert {card['priority']}" if card["has_alert"] else "") + (" · contains SYNTHETIC data" if card["contains_synthetic"] else ""))
                if card["affected_resources"]:
                    md("Affected: " + ", ".join(card["affected_resources"]))
                st.button("Investigate", key=f"open_{card['incident_id']}", on_click=_open_incident, args=(card["incident_id"],))
    with right:
        st.subheader("Reduction: events → investigations")
        rows = vm.funnel_rows(k)
        fig = go.Figure(go.Funnel(y=[r["stage"] for r in rows], x=[r["count"] for r in rows]))
        fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=280)
        st.plotly_chart(fig)
        st.subheader("Suspicious sessions")
        st.dataframe([{k2: s.get(k2) for k2 in ("session_key", "event_count", "finding_count", "rule_ids", "last_seen")} for s in sessions])

    st.subheader("Recent events (refresh the page for near-live updates)")
    st.dataframe([{k2: e.get(k2) for k2 in ("timestamp", "event_type", "source", "source_ip", "session_id", "method", "endpoint", "status_code", "is_synthetic")}
                  for e in events])


# ----------------------------------------------------------------------------------------------- investigation
def investigation_page(site: dict) -> None:
    st.header("Incident investigation")
    c = client()
    try:
        incidents = c.incidents(site["website_id"])
    except ApiError as e:
        show_error(e)
        return
    if not incidents:
        st.info("No incidents to investigate yet.")
        return
    ids = [i["incident_id"] for i in incidents]
    cur = st.session_state.get("incident_id")
    inc_id = st.selectbox("Incident", ids, index=ids.index(cur) if cur in ids else 0,
                          format_func=lambda i: next(vm.md_escape(x["title"], 80) for x in incidents if x["incident_id"] == i))
    st.session_state.incident_id = inc_id

    if st.button("Run investigation (anomaly → threat intel → risk → AI agents → alert)"):
        with st.spinner("Investigating... (the AI step can take a while on a free-tier model)"):
            try:
                res = c.investigate(inc_id)
                (st.success if res.get("status") == "ok" else st.warning)(f"Investigation status: {res.get('status')}")
                if res.get("error"):
                    st.error(vm.error_banner("llm_unavailable" if res.get("status") == "llm_unavailable" else "", str(res["error"])[:200]))
            except ApiError as e:
                show_error(e)
    try:
        inc, risk, tl = c.incident(inc_id), c.risk(inc_id), c.timeline(inc_id)
        graph, ti = c.graph(inc_id), c.threat_intel(inc_id)
        inv, rec = c.investigation(inc_id), c.recommendations(inc_id)
        audit = c.audit(inc_id)
        lc, fb = c.lifecycle(inc_id), c.feedback(inc_id)
    except ApiError as e:
        show_error(e)
        return
    _show_flash()

    tabs = st.tabs(["Summary", "Timeline", "Attack graph", "Evidence & AI", "Threat intelligence", "Risk", "Response", "Analyst actions", "Report"])
    with tabs[0]:
        level = (inc.get("risk_level") or "NOT SCORED").upper()
        st.markdown(f"## {vm.md_escape(inc['title'])}")
        st.markdown(badge(level) + f" &nbsp; score **{inc.get('risk_score')}** · evidence confidence **{inc.get('confidence')}** · status **{inc.get('status')}**")
        d = inc.get("details") or {}
        md("Affected resources: " + (", ".join(d.get("affected_resources") or []) or "none recorded"))
        for lim in d.get("limitations") or []:
            md("• Limitation: " + lim)
        st.caption("Risk comes from documented, configuration-driven scoring; confidence is evidence quality. Neither is a probability.")
    with tabs[1]:
        rows = vm.timeline_rows(tl.get("timeline"))
        if rows:
            fig = go.Figure(go.Scatter(x=[r["timestamp"] for r in rows], y=list(range(len(rows), 0, -1)), mode="markers+text",
                                       text=[r["label"][:60] for r in rows], textposition="middle right",
                                       marker=dict(size=12, color=[r["color"] for r in rows]),
                                       hovertext=[f"{r['evidence_label']}<br>events: {r['event_ids_short']}" for r in rows], hoverinfo="text"))
            fig.update_yaxes(visible=False)
            fig.update_layout(height=120 + 38 * len(rows), margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig)
            st.dataframe([{"time": r["timestamp"], "event": r["label"], "type": r["evidence_label"], "events": r["event_count"], "event ids": r["event_ids_short"]} for r in rows])
        else:
            st.info("No timeline entries.")
    with tabs[2]:
        lay = vm.graph_layout(graph)
        if lay["nodes"]:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=[v for e in lay["edges"] for v in (e["x0"], e["x1"], None)], y=[v for e in lay["edges"] for v in (e["y0"], e["y1"], None)],
                                     mode="lines", line=dict(width=1.5, color="#a0aec0"), hoverinfo="skip"))
            fig.add_trace(go.Scatter(x=[n["x"] for n in lay["nodes"]], y=[n["y"] for n in lay["nodes"]], mode="markers+text",
                                     text=[n["label"][:28] for n in lay["nodes"]], textposition="bottom center", marker=dict(size=18, color="#2b6cb0"),
                                     hovertext=[f"{n['type']}<br>{n['event_count']} events<br>ids: {vm.short_ids(n['event_ids'])}" for n in lay["nodes"]], hoverinfo="text"))
            fig.update_xaxes(visible=False)
            fig.update_yaxes(visible=False)
            fig.update_layout(showlegend=False, height=460, margin=dict(l=0, r=0, t=10, b=40))
            st.plotly_chart(fig)
            st.caption("Derived presentation layer: every node and edge lists the event ids it rests on.")
            st.dataframe([{"edge": e["relationship"], "from": e["source"], "to": e["target"], "evidence": vm.evidence_label(e["evidence_type"]),
                           "event ids": vm.short_ids(e["event_ids"])} for e in lay["edges"]])
        else:
            st.info("No graph available.")
    with tabs[3]:
        v = vm.investigation_view(inv)
        if v["status"] == "not_run":
            st.info("The AI investigation has not been run for this incident. Facts below are deterministic.")
        elif v["status"] != "ok":
            err = v["error"].get("message") if isinstance(v["error"], dict) else v["error"]       # the backend sends {"code", "message"}
            st.warning(f"AI investigation status: {v['status']}. " + (vm.md_escape(err) if err else ""))
        if v.get("stale"):
            st.warning("This investigation may be out of date: " + vm.md_escape("; ".join(v["stale_reasons"])))
        st.subheader("Observed facts and derived metrics (authored by code)")
        for f in v["facts"]:
            md(f"[{f['label']}] {f['text']}   (refs: {', '.join(f['refs'])})")
        st.subheader("AI inference (not proof)")
        if v["hypothesis"]:
            h = v["hypothesis"]
            md(f"Hypothesis: {h['statement']}")
            st.caption(f"Category {h['category']} · confidence {h['confidence']} ({h['basis']}) · event ids: {vm.short_ids(h['event_ids'])}")
            for cl in v["claims"]:
                md(f"• {cl['claim']}  [events: {vm.short_ids(cl['event_ids'])}]")
            st.subheader("Missing evidence")
            for g in vm.evidence_gap_rows(risk, inv):
                md(f"• ({g['source'].replace('_', ' ')}) {g['text']}")
            if v["alternatives"]:
                st.subheader("Alternative explanations")
                for a in v["alternatives"]:
                    md("• " + a)
            val = v["validation"]
            st.caption(f"Grounding check: {val.get('claims_kept')}/{val.get('claims_received')} claims kept, {val.get('unsupported_claims_dropped')} unsupported dropped, "
                       f"{val.get('invalid_refs_removed')} invalid references removed.")
        else:
            st.info("No grounded AI hypothesis available.")
        if v.get("disclaimer"):
            st.caption(v["disclaimer"])
    with tabs[4]:
        t = vm.ti_rows(ti)
        if t["banner"]:
            st.warning(t["banner"]) if t["has_synthetic"] else st.info(t["banner"])
        if t["status"] == "not_run":
            st.info("Threat-intelligence enrichment has not been run. It runs as part of the investigation.")
        for r in t["rows"]:
            with st.container(border=True):
                md(f"{r['indicator_type']}: {r['indicator']} · provider {r['provider']} · status {r['status']}" + (" · SYNTHETIC" if r["synthetic"] else ""))
                md(r["summary"])
                for lim in r["limitations"]:
                    md("• " + lim)
    with tabs[5]:
        rows = vm.risk_factor_rows(risk)
        st.markdown(f"**Risk {risk.get('risk_level')} · score {risk.get('risk_score')} · evidence confidence {risk.get('confidence')}**" if risk.get("status") == "ok"
                    else "Risk has not been scored.")
        if rows:
            fig = go.Figure(go.Bar(x=[r["points"] for r in rows][::-1], y=[r["factor"] for r in rows][::-1], orientation="h"))
            fig.update_layout(height=60 + 34 * len(rows), margin=dict(l=0, r=0, t=10, b=0), xaxis_title="points contributed")
            st.plotly_chart(fig)
            st.dataframe([{k2: r[k2] for k2 in ("factor", "status", "weight", "value", "points", "basis")} for r in rows])
        for g in vm.evidence_gap_rows(risk):
            md("• Evidence gap: " + g["text"])
    with tabs[6]:
        recs = vm.recommendation_rows(rec)
        decided = {d["action"]: d for d in vm.recommendation_decision_rows(rec)}
        st.info(rec.get("approval_note") or "Recommendations are proposals. Nothing is executed; every action requires analyst approval.")
        if not recs:
            st.write("No recommendations generated yet.")
        for r in recs:
            with st.container(border=True):
                md(f"P{r['priority']} · {r['title']}  ({r['action']})")
                md(r["rationale"])
                if r["limitations"]:
                    md("Limitation: " + r["limitations"])
                st.caption(f"Status: {r['status']} · requires human approval: {r['requires_human_approval']} · executed: {r['executed']} · events: {vm.short_ids(r['event_ids'])}")
                st.caption("Analyst: " + decided.get(r["action"], {}).get("decision_label", "Awaiting analyst decision") + " (decide in the Analyst actions tab)")
        with st.expander("Audit trail of AI recommendations and alerts"):
            st.dataframe([{k2: a.get(k2) for k2 in ("at", "action", "actor", "agent", "model", "priority")} for a in audit.get("audit", [])])
    with tabs[7]:
        analyst_actions_tab(inc_id, lc, rec, fb)
    with tabs[8]:
        report_tab(inc_id)


# ----------------------------------------------------------------------------------------------- analyst actions + report (M10 Part 2)
def analyst_actions_tab(inc_id: str, lc: dict, rec: dict, fb: dict) -> None:
    """PRD sections 21-22: decision + comment (feedback table), accept / reject / investigate further per recommendation, lifecycle steps."""
    c = client()
    s = vm.lifecycle_summary(lc)
    st.markdown(f"**Status:** {s['status_label']} · alert {s['alert_status']} · analyst outcomes stored: {s['feedback_count']}")
    if s["latest_decision"]:
        md(f"Latest analyst decision: {s['latest_decision']}" + (f" - {s['latest_comment']}" if s["latest_comment"] else ""))
    st.info("These controls record human decisions only. The platform never blocks, isolates or changes anything on its own; "
            "ACTION_TAKEN means a person did something outside this platform.")

    st.subheader("1. Analyst decision")
    labels = dict(vm.ANALYST_DECISIONS)
    with st.form(f"decision_{inc_id}"):
        choice = st.radio("Outcome of your review", [k for k, _ in vm.ANALYST_DECISIONS], format_func=labels.get, key=f"dec_choice_{inc_id}")
        note = st.text_area("Comment (optional, plain text, max 2000 characters)", max_chars=2000, key=f"dec_note_{inc_id}")
        submitted = st.form_submit_button("Save decision")
    if submitted:
        _do_action(lambda: c.post_feedback(inc_id, choice, (note or "").strip() or None), "Decision saved against the incident (feedback table).")
    st.caption("Stored for later tuning of rules, prompts and baselines. There is no autonomous online learning loop.")

    st.subheader("2. Recommended responses: accept, reject or investigate further")
    rows = vm.recommendation_decision_rows(rec)
    if not rows:
        st.write("No recommendations yet. Run the investigation first (Response agent output).")
    for r in rows:
        with st.container(border=True):
            md(f"P{r['priority']} · {r['title']}  ({r['action']})")
            st.caption(f"{r['decision_label']} · executed: {r['executed']}")
            if r["comment"]:
                md("Analyst comment: " + r["comment"])
            rc = st.text_input("Comment (optional)", max_chars=500, key=f"rc_{inc_id}_{r['action']}")
            for col, (val, label) in zip(st.columns(len(vm.RECOMMENDATION_CHOICES)), vm.RECOMMENDATION_CHOICES):
                with col:
                    if st.button(label, key=f"rd_{inc_id}_{r['action']}_{val}"):
                        _do_action(lambda a=r["action"], v=val, n=rc: c.decide_recommendation(inc_id, a, v, (n or "").strip() or None),
                                   f"Recorded: {label} for {r['action']}. Nothing was executed.")

    st.subheader("3. Move the incident through the lifecycle")
    prog = vm.approval_progress(rows)
    if not s["step_options"]:
        st.caption(f"No manual lifecycle step is available from {s['status_label']}. Use the decision form above, or reopen a resolved incident when offered.")
    else:
        with st.form(f"step_{inc_id}"):
            target = st.selectbox("Move to", s["step_options"], format_func=vm.status_label, key=f"step_to_{inc_id}")
            step_note = st.text_area("Comment (required when recording ACTION_TAKEN)", max_chars=2000, key=f"step_note_{inc_id}")
            go = st.form_submit_button("Update status")
        if "ACTION_TAKEN" in s["step_options"] and not prog["can_record_action_taken"]:
            st.caption("Recording ACTION_TAKEN needs at least one accepted recommendation (human approval).")
        if go:
            _do_action(lambda: c.set_status(inc_id, target, (step_note or "").strip() or None), "Status updated.")

    with st.expander("Status history"):
        st.dataframe(vm.history_rows(lc))
    with st.expander("Stored analyst outcomes (feedback)"):
        st.dataframe(vm.feedback_rows(fb))


def report_tab(inc_id: str) -> None:
    """PRD section 24: structured, shareable incident report, generated on request from stored data (deterministic; no AI call)."""
    c = client()
    key = f"report_{inc_id}"
    st.caption("The report is assembled from stored, already-validated data. Observed facts, AI inference and missing evidence stay labelled separately.")
    if st.button("Generate incident report", key=f"gen_{key}"):
        with st.spinner("Generating report..."):
            try:
                st.session_state[key] = {"markdown": c.report(inc_id, "markdown"), "html": c.report(inc_id, "html"), "json": c.report(inc_id, "json")}
            except ApiError as e:
                if e.kind == "unauthorized":
                    show_error(e)
                else:
                    st.error(vm.action_error_text(e.kind, e.message, e.code))
    rep = st.session_state.get(key)
    if not rep:
        st.info("Press the button to generate the report. It reflects the incident as stored right now, including analyst decisions.")
        return
    for fmt, label in (("markdown", "Download Markdown"), ("html", "Download HTML"), ("json", "Download JSON")):
        meta = vm.report_download(inc_id, fmt)
        data = json.dumps(rep[fmt], indent=2, ensure_ascii=False) if fmt == "json" else rep[fmt]
        st.download_button(label, data=data, file_name=meta["file_name"], mime=meta["mime"], key=f"dl_{key}_{fmt}")
    with st.expander("Preview (Markdown)"):
        st.markdown(rep["markdown"])


# ----------------------------------------------------------------------------------------------- main
def main() -> None:
    boot_error = _bootstrap_backend()
    if boot_error:
        st.error(boot_error)
        return
    c = client()
    if not c.token:
        auth_page()
        return
    st.sidebar.title("🛡️ WebIntelX AI")
    st.sidebar.caption(st.session_state.get("email", ""))
    try:
        sites = c.websites()
    except ApiError as e:
        show_error(e)
        if st.sidebar.button("Sign out"):
            st.session_state.clear()
            st.rerun()
        return
    if "goto_page" in st.session_state:                    # must run BEFORE the radio is created (Streamlit forbids setting a widget key afterwards)
        st.session_state.page = st.session_state.pop("goto_page")
    page = st.sidebar.radio("Page", ["Dashboard", "Incident investigation", "Onboarding"], key="page") if sites else "Onboarding"
    if sites and page != "Onboarding":
        site = _pick_site(sites)
        (dashboard_page if page == "Dashboard" else investigation_page)(site)
    else:
        onboarding_page(sites)
    if st.sidebar.button("Sign out"):
        try:
            c.logout()
        except ApiError:
            pass
        st.session_state.clear()
        st.rerun()


main()
