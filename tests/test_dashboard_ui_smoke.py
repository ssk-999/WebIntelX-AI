"""M9 UI smoke test: runs the real dashboard/streamlit_app.py code paths against a STUBBED streamlit/plotly and a fake API client
returning real-shaped data (M8 outputs). It catches NameErrors, wrong keys and crashes in our UI code. It does NOT validate Streamlit's
own API (that needs the real package - see README 'Verification status of M9'). Plain asserts; no network, no DB."""
import importlib
import sys
import types
from unittest.mock import MagicMock

from app.agents.config import defaults
from app.crew.orchestration import investigate_core
from dashboard.api_client import ApiError
from tests.agent_helpers import GOOD_INVESTIGATION, GOOD_RESPONSE, FakeRunner, make_findings, make_incident, make_timeline
from tests.test_dashboard_viewmodels import GRAPH


class _SS(dict):
    __getattr__ = dict.get

    def __setattr__(self, k, v):
        self[k] = v


class FakeClient:
    token = "tok"

    def __init__(self, fail=None, not_run=False, refuse=False):
        self.calls, self.refuse = [], refuse
        inc = make_incident("HIGH")
        out = investigate_core(incident=inc, findings=make_findings(), timeline=make_timeline(),
                               runner=FakeRunner([GOOD_INVESTIGATION, GOOD_RESPONSE]), cfg=defaults())
        self.fail, self.not_run, self.out, self.inc = fail, not_run, out, inc

    def _maybe(self):
        if self.fail:
            raise ApiError(self.fail, "boom")

    def websites(self): self._maybe(); return [{"website_id": "w1", "domain": "demo.example.com"}]
    def verification(self, w): self._maybe(); return {"status": "active", "events_received": 144}
    def incidents(self, w): return [{"incident_id": "inc_test1", "title": "Possible credential abuse", "risk_level": "HIGH", "risk_score": 81.9,
                                     "confidence": 0.6, "status": "DETECTED", "details": self.inc["details"]}]
    def alerts(self, w): return {"alerts": [self.out["alert"]]}
    def findings(self, w, limit=500): return [{"event_id": "e1", "evidence": {"event_ids": ["e1", "e2"]}}]
    def events(self, w, limit=15): return [{"timestamp": "t", "event_type": "login_failure", "endpoint": "/login", "is_synthetic": True}]
    def sessions(self, w, **kw): return [{"session_key": "s1", "event_count": 3, "finding_count": 1, "rule_ids": ["R-AUTH-001"], "last_seen": "t"}]
    def incident(self, i): return {"incident_id": i, "title": "Possible credential abuse", "risk_level": "HIGH", "risk_score": 81.9, "confidence": 0.6,
                                   "status": "DETECTED", "details": self.inc["details"]}
    def risk(self, i): return self.inc["details"]["risk"]
    def timeline(self, i): return {"timeline": make_timeline()}
    def graph(self, i): return GRAPH
    def threat_intel(self, i): return {"status": "not_run", "results": [], "notes": []}
    def investigation(self, i): return {"status": "not_run", "notes": []} if self.not_run else self.out["investigation"]
    def recommendations(self, i): return self.out["recommendations"]
    def audit(self, i): return {"audit": self.out["audit"]}
    def investigate(self, i): return {"status": "llm_unavailable", "error": {"kind": "no_key"}}
    def logout(self): self.token = None

    # ---- M10 Part 2 (shapes follow the real M10 Part 1 API)
    def lifecycle(self, i): return {"incident_id": i, "status": "DETECTED", "closed": False, "feedback_count": 0, "latest_feedback": None, "alert_status": "open",
                                    "allowed_next": ["INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"], "recommendation_decisions": {},
                                    "history": [{"at": "t", "from": "DETECTED", "to": "INVESTIGATING", "actor": "system", "reason": "investigation_run"}], "updated_at": "t"}
    def feedback(self, i): return {"incident_id": i, "count": 0, "feedback": []}

    def _act(self, name, *args):
        self.calls.append((name, *args))
        if self.refuse:
            raise ApiError("client_error", "No recommended response has been accepted yet.", 409, "approval_required")
        return {"ok": True}

    def post_feedback(self, i, decision, comment=None): return self._act("post_feedback", i, decision, comment)
    def set_status(self, i, status, comment=None): return self._act("set_status", i, status, comment)
    def decide_recommendation(self, i, action, decision, comment=None): return self._act("decide_recommendation", i, action, decision, comment)

    def report(self, i, fmt="json"):
        self.calls.append(("report", i, fmt))
        return {"incident_id": i} if fmt == "json" else ("# Incident report" if fmt == "markdown" else "<html></html>")


def _run_app(client, page, button_value=False, submit_value=False):
    st = MagicMock(name="streamlit")
    st.session_state = _SS(client=client, page=page, website_id="w1", email="a@b.c")
    st.secrets = {}
    st._cols = []

    def _columns(spec, **k):
        cols = [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]
        st._cols.extend(cols)
        return cols

    st.columns.side_effect = _columns
    st.tabs.side_effect = lambda names: [MagicMock() for _ in names]
    st.button.return_value = button_value
    st.form_submit_button.return_value = submit_value
    st.sidebar.radio.return_value = page
    st.sidebar.button.return_value = False
    st.sidebar.selectbox.side_effect = lambda label, options, **k: options[0]
    st.selectbox.side_effect = lambda label, options, **k: options[0]
    saved = {k: sys.modules.get(k) for k in ("streamlit", "plotly", "plotly.graph_objects", "dashboard.streamlit_app")}
    plotly = types.ModuleType("plotly")
    sys.modules.update({"streamlit": st, "plotly": plotly, "plotly.graph_objects": MagicMock(name="go")})
    plotly.graph_objects = sys.modules["plotly.graph_objects"]
    sys.modules.pop("dashboard.streamlit_app", None)
    try:
        importlib.import_module("dashboard.streamlit_app")   # runs main() at import, like a Streamlit script run
    finally:
        for k, v in saved.items():
            sys.modules.pop(k, None)
            if v is not None:
                sys.modules[k] = v
    return st


def _text(st) -> str:
    return " ".join(str(c) for c in st.method_calls)


def test_dashboard_page_renders_kpis_cards_and_funnel():
    st = _run_app(FakeClient(), "Dashboard")
    t = _text(st)
    assert "Security Dashboard" in t and "Investigate" in t
    metrics = [str(c) for col in st._cols for c in col.metric.call_args_list]
    assert len(metrics) == 5 and any("144" in m for m in metrics) and any("High-risk incidents" in m and "1" in m for m in metrics)
    assert not st.error.called


def test_investigation_page_renders_all_tabs_with_real_shaped_data():
    st = _run_app(FakeClient(), "Incident investigation")
    t = _text(st)
    assert "Incident investigation" in t and "AI inference (not proof)" in t and "Missing evidence" in t and "Analyst decision" in t
    assert not st.error.called


def test_investigation_page_with_ai_not_run_is_informational_not_an_error():
    st = _run_app(FakeClient(not_run=True), "Incident investigation")
    assert "has not been run" in _text(st) and not st.error.called


def test_run_investigation_button_surfaces_llm_unavailable_without_crashing():
    st = _run_app(FakeClient(), "Incident investigation", button_value=True)
    assert st.warning.called and st.error.called
    assert "language model is unavailable" in str(st.error.call_args)


def test_backend_down_shows_banner_instead_of_crashing():
    st = _run_app(FakeClient(fail="backend_down"), "Dashboard")
    assert st.error.called and "unreachable" in str(st.error.call_args)


def test_expired_session_clears_client_and_asks_to_sign_in_again():
    c = FakeClient(fail="unauthorized")
    st = _run_app(c, "Dashboard")
    assert "client" not in st.session_state and "sign in again" in str(st.error.call_args)


def test_analyst_actions_tab_offers_decision_recommendation_and_lifecycle_controls():
    st = _run_app(FakeClient(), "Incident investigation")
    t = _text(st)
    assert "Analyst decision" in t and "Accept" in t and "Further investigate" in t and "Move the incident through the lifecycle" in t
    assert "Generate incident report" in t and "never blocks, isolates or changes anything" in t
    assert not st.error.called


def test_saving_a_decision_and_a_status_step_calls_the_backend_and_refreshes():
    c = FakeClient()
    st = _run_app(c, "Incident investigation", submit_value=True)
    names = [x[0] for x in c.calls]
    assert "post_feedback" in names and "set_status" in names and st.rerun.called
    assert not any("execute" in n for n in names) and not st.error.called


def test_recommendation_buttons_record_accept_reject_and_further_investigation_only():
    c = FakeClient()
    _run_app(c, "Incident investigation", button_value=True)
    decisions = {x[3] for x in c.calls if x[0] == "decide_recommendation"}
    assert decisions == {"accept", "reject", "further_investigation"}


def test_refused_action_shows_the_backend_message_and_does_not_refresh():
    c = FakeClient(refuse=True)
    st = _run_app(c, "Incident investigation", submit_value=True)
    assert st.warning.called and "Approval needed" in str(st.warning.call_args) and not st.rerun.called and not st.error.called


def test_report_tab_generates_the_report_and_offers_three_downloads():
    c = FakeClient()
    st = _run_app(c, "Incident investigation", button_value=True)
    fmts = {x[2] for x in c.calls if x[0] == "report"}
    assert fmts == {"markdown", "html", "json"}
    names = [str(call.kwargs.get("file_name")) for call in st.download_button.call_args_list]
    assert len(names) == 3 and all(n.endswith(("-report.md", "-report.html", "-report.json")) for n in names)


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(exc))
    print("failures:", fails)
