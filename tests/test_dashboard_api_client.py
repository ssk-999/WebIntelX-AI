"""M9 API-client tests using httpx.MockTransport (no network). Needs httpx, so it is NOT executed in the sandbox that built M9;
run `python -m pytest tests/test_dashboard_api_client.py` locally. Plain asserts, no pytest import."""
import httpx

from dashboard.api_client import ApiClient, ApiError


def _client(handler, token=None):
    return ApiClient("http://backend.test", token=token, transport=httpx.MockTransport(handler))


def _raises(fn, kind):
    try:
        fn()
    except ApiError as e:
        assert e.kind == kind, (e.kind, kind)
        return e
    raise AssertionError("ApiError not raised")


def test_login_stores_token_and_sends_bearer_header_afterwards():
    seen = []

    def handler(req):
        seen.append((req.url.path, req.headers.get("authorization")))
        return httpx.Response(200, json={"access_token": "tok123", "expires_at": "x"} if req.url.path.endswith("login") else [])

    c = _client(handler)
    c.login("a@b.co", "password1")
    c.websites()
    assert c.token == "tok123" and seen[0] == ("/v1/auth/login", None) and seen[1] == ("/v1/websites", "Bearer tok123")


def test_http_errors_map_to_kinds_and_never_include_the_token():
    codes = {401: "unauthorized", 404: "not_found", 503: "database", 422: "client_error", 500: "server_error"}
    for status, kind in codes.items():
        e = _raises(lambda s=status: _client(lambda r, s=s: httpx.Response(s, json={"detail": "nope"}), token="SECRET-TOKEN").websites(), kind)
        assert "SECRET-TOKEN" not in e.message and e.status == status


def test_unreachable_backend_and_timeouts_become_backend_down():
    def refuse(_req):
        raise httpx.ConnectError("refused")

    def slow(_req):
        raise httpx.ReadTimeout("slow")

    _raises(lambda: _client(refuse).websites(), "backend_down")
    _raises(lambda: _client(slow).websites(), "backend_down")


def test_non_json_error_body_is_handled_and_204_returns_none():
    e = _raises(lambda: _client(lambda r: httpx.Response(502, text="<html>bad gateway</html>")).websites(), "server_error")
    assert "<html>" not in e.message
    assert _client(lambda r: httpx.Response(204)).post("/v1/auth/logout") is None


def test_query_params_drop_none_and_paths_are_exact():
    seen = []
    _client(lambda r: (seen.append(str(r.url)) or httpx.Response(200, json=[]))).events("w1", limit=5)
    _client(lambda r: (seen.append(str(r.url)) or httpx.Response(200, json={}))).get("/v1/x", a=None, b=1)
    assert seen[0] == "http://backend.test/v1/websites/w1/events?limit=5" and seen[1] == "http://backend.test/v1/x?b=1"
