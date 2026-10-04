"""M10 Part 2: ApiClient lifecycle / feedback / decision / report methods and the structured lifecycle error format.
Uses httpx.MockTransport (no network). Plain asserts, no pytest import."""
import json

import httpx

from dashboard.api_client import ApiClient, ApiError


def _client(handler, token="tok"):
    return ApiClient("http://backend.test", token=token, transport=httpx.MockTransport(handler))


def _err(fn):
    try:
        fn()
    except ApiError as e:
        return e
    raise AssertionError("ApiError not raised")


def test_lifecycle_error_detail_dict_yields_message_and_code_not_a_generic_text():
    body = {"detail": {"code": "approval_required", "message": "Accept at least one recommendation first.", "recommendations": ["a"]}}
    e = _err(lambda: _client(lambda r: httpx.Response(409, json=body)).set_status("inc1", "ACTION_TAKEN", "x"))
    assert e.kind == "client_error" and e.status == 409 and e.code == "approval_required"
    assert e.message == "Accept at least one recommendation first."


def test_string_list_and_malformed_details_stay_safe():
    e = _err(lambda: _client(lambda r: httpx.Response(404, json={"detail": "Incident not found"})).lifecycle("x"))
    assert e.kind == "not_found" and e.message == "Incident not found" and e.code is None
    e = _err(lambda: _client(lambda r: httpx.Response(422, json={"detail": [{"loc": ["body"], "msg": "bad"}]})).post_feedback("x", "nope"))
    assert e.message == "Request rejected" and e.code is None
    e = _err(lambda: _client(lambda r: httpx.Response(409, json={"detail": {"code": 5, "message": ""}})).set_status("x", "RESOLVED"))
    assert e.message == "Request rejected" and e.code is None


def test_secret_token_never_appears_in_an_error():
    e = _err(lambda: _client(lambda r: httpx.Response(409, json={"detail": {"code": "invalid_transition", "message": "no"}}), token="SECRET-TOKEN").set_status("i", "RESOLVED"))
    assert "SECRET-TOKEN" not in e.message and "SECRET-TOKEN" not in str(e)


def test_new_endpoints_use_exact_paths_methods_and_bodies():
    seen = []

    def handler(req):
        seen.append((req.method, req.url.path, json.loads(req.content) if req.content else None, req.headers.get("authorization")))
        return httpx.Response(200, json={})

    c = _client(handler)
    c.lifecycle("inc_1")
    c.feedback("inc_1")
    c.post_feedback("inc_1", "confirmed", "looks real")
    c.set_status("inc_1", "RESOLVED", None)
    c.decide_recommendation("inc_1", "reset_credentials", "accept", "ok")
    assert seen[0][:2] == ("GET", "/v1/incidents/inc_1/lifecycle")
    assert seen[1][:2] == ("GET", "/v1/incidents/inc_1/feedback")
    assert seen[2][:3] == ("POST", "/v1/incidents/inc_1/feedback", {"decision": "confirmed", "comment": "looks real"})
    assert seen[3][:3] == ("POST", "/v1/incidents/inc_1/status", {"status": "RESOLVED", "comment": None})
    assert seen[4][:3] == ("POST", "/v1/incidents/inc_1/recommendations/reset_credentials/decision", {"decision": "accept", "comment": "ok"})
    assert all(x[3] == "Bearer tok" for x in seen)


def test_report_returns_text_for_markdown_and_html_and_a_dict_for_json():
    def handler(req):
        fmt = req.url.params["format"]
        if fmt == "json":
            return httpx.Response(200, json={"incident_id": "inc_1"})
        return httpx.Response(200, text="# Report" if fmt == "markdown" else "<!doctype html>", headers={"content-type": "text/plain"})

    c = _client(handler)
    assert c.report("inc_1", "json") == {"incident_id": "inc_1"}
    assert c.report("inc_1", "markdown") == "# Report" and c.report("inc_1", "html").startswith("<!doctype")
    try:
        c.report("inc_1", "pdf")
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown format must be refused before any request")


def test_report_errors_are_controlled():
    e = _err(lambda: _client(lambda r: httpx.Response(404, json={"detail": "Incident not found"})).report("nope", "markdown"))
    assert e.kind == "not_found"


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
