"""M10 Part 2 view-model tests (analyst actions, lifecycle, report). Pure functions: no Streamlit, no network, no DB. Plain asserts."""
from dashboard import viewmodels as vm

LC = {"incident_id": "inc_1", "status": "RESPONSE_RECOMMENDED", "closed": False, "feedback_count": 2, "alert_status": "acknowledged",
      "allowed_next": ["ACTION_TAKEN", "RESOLVED", "NEEDS_INVESTIGATION"],
      "latest_feedback": {"analyst_decision": "CONFIRMED", "comment": "real", "created_at": "t2"},
      "history": [{"at": "t1", "from": "DETECTED", "to": "CONFIRMED", "actor": "analyst:a1", "reason": "analyst_decision", "comment": "<b>x</b>"},
                  {"at": "t2", "from": "CONFIRMED", "to": "RESPONSE_RECOMMENDED", "actor": "system", "reason": "confirmed_with_recommendations"}]}
REC = {"recommendations": [
    {"action": "monitor", "title": "Monitor", "priority": 2, "analyst_decision": None},
    {"action": "reset_credentials", "title": "Reset credentials", "priority": 1,
     "analyst_decision": {"decision": "accepted", "comment": "ok", "decided_at": "t", "decided_by": "analyst:a1"}}]}


def test_step_options_exclude_the_three_decision_states():
    assert vm.lifecycle_step_options({"allowed_next": ["INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"]}) == ["INVESTIGATING"]
    assert vm.lifecycle_step_options(LC) == ["ACTION_TAKEN", "RESOLVED"]
    assert vm.lifecycle_step_options(None) == [] and vm.lifecycle_step_options({}) == []


def test_lifecycle_summary_handles_missing_data_and_labels_states():
    s = vm.lifecycle_summary(LC)
    assert s["status"] == "RESPONSE_RECOMMENDED" and s["latest_decision"] == "CONFIRMED" and s["feedback_count"] == 2 and s["alert_status"] == "acknowledged"
    empty = vm.lifecycle_summary(None)
    assert empty["status"] == "DETECTED" and empty["alert_status"] == "n/a" and empty["latest_decision"] is None and empty["step_options"] == []
    assert "outside this platform" in vm.status_label("ACTION_TAKEN") and vm.status_label(None) == "Detected" and vm.status_label("WEIRD_STATE") == "Weird State"


def test_history_is_newest_first_limited_and_keeps_comments_as_plain_data():
    rows = vm.history_rows(LC)
    assert [r["to"] for r in rows] == ["RESPONSE_RECOMMENDED", "CONFIRMED"] and rows[1]["comment"] == "<b>x</b>" and rows[0]["comment"] == ""
    assert len(vm.history_rows({"history": [{"to": str(i)} for i in range(50)]}, limit=5)) == 5 and vm.history_rows(None) == []


def test_recommendation_decision_rows_overlay_never_claim_execution():
    rows = vm.recommendation_decision_rows(REC)
    assert [r["action"] for r in rows] == ["reset_credentials", "monitor"]
    assert rows[0]["decision"] == "accepted" and rows[0]["decision_label"] == "Accepted by analyst" and rows[0]["comment"] == "ok"
    assert rows[1]["decision"] is None and rows[1]["decision_label"] == "Awaiting analyst decision"
    assert all(r["executed"] is False for r in rows)
    forged = vm.recommendation_decision_rows({"recommendations": [{"action": "block_ip", "executed": True, "analyst_decision": "accepted"}]})
    assert forged[0]["executed"] is False and forged[0]["decision"] is None
    assert vm.recommendation_decision_rows(None) == []


def test_approval_progress_mirrors_the_backend_gate_for_action_taken():
    assert vm.approval_progress([])["can_record_action_taken"] is True
    pending = vm.approval_progress(vm.recommendation_decision_rows({"recommendations": [{"action": "a", "priority": 1}]}))
    assert pending == {"total": 1, "accepted": 0, "pending": 1, "can_record_action_taken": False}
    done = vm.approval_progress(vm.recommendation_decision_rows(REC))
    assert done["accepted"] == 1 and done["pending"] == 1 and done["can_record_action_taken"] is True
    rejected = vm.approval_progress([{"decision": "rejected"}])
    assert rejected["can_record_action_taken"] is False


def test_feedback_rows_shape():
    rows = vm.feedback_rows({"feedback": [{"feedback_id": "fb1", "analyst_decision": "FALSE_POSITIVE", "comment": None, "created_at": "t"}]})
    assert rows == [{"at": "t", "decision": "FALSE_POSITIVE", "comment": "", "feedback_id": "fb1"}] and vm.feedback_rows(None) == []


def test_report_download_names_are_safe_and_formats_validated():
    assert vm.report_download("inc_ab12", "markdown") == {"file_name": "inc_ab12-report.md", "mime": "text/markdown"}
    assert vm.report_download("inc_1", "html")["file_name"].endswith(".html") and vm.report_download("inc_1", "json")["mime"] == "application/json"
    evil = vm.report_download('../../etc/passwd"; x=', "markdown")["file_name"]
    assert "/" not in evil and '"' not in evil and " " not in evil and evil.endswith("-report.md")
    assert vm.report_download(None, "html")["file_name"] == "incident-report.html"
    try:
        vm.report_download("inc_1", "pdf")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown format must raise")


def test_action_error_text_uses_the_backend_message_escaped_and_connection_banners():
    t = vm.action_error_text("client_error", "Accept <b>first</b> [x](http://e)", "approval_required")
    assert t.startswith("Approval needed: ") and "<b>" not in t and "\\[x\\]" in t
    assert vm.action_error_text("client_error", "nope", "invalid_transition").startswith("Not allowed from the current state: ")
    assert vm.action_error_text("client_error", "need one", "comment_required").startswith("Comment needed: ")
    assert vm.action_error_text("client_error", "x", None).startswith("Request refused: ")
    assert "unreachable" in vm.action_error_text("backend_down", "detail") and "expired" in vm.action_error_text("unauthorized", "tok")
    assert "tok" not in vm.action_error_text("unauthorized", "tok")


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
