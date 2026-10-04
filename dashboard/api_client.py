"""Thin HTTP client for the WebIntelX AI backend (the dashboard never touches the database directly).

Failures never leak tokens: `ApiError.message` carries only the backend's `detail` text or a generic description."""
from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


class ApiError(Exception):
    """kind: backend_down | unauthorized | not_found | database | client_error | server_error"""

    def __init__(self, kind: str, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.kind, self.message, self.status, self.code = kind, message, status, code   # `code`: M10 lifecycle error code, e.g. invalid_transition


def _kind(status: int) -> str:
    return {401: "unauthorized", 404: "not_found", 503: "database"}.get(status, "client_error" if status < 500 else "server_error")


def _parse_error(resp: httpx.Response) -> tuple[str, str | None]:
    """(message, code). M10 lifecycle errors send `detail` as {"code", "message", ...}; older routes send a plain string."""
    try:
        d = resp.json().get("detail")
    except Exception:  # noqa: BLE001 - any non-JSON body
        return f"HTTP {resp.status_code}", None
    if isinstance(d, str):
        return d, None
    if isinstance(d, dict):
        msg, code = d.get("message"), d.get("code")
        return (msg if isinstance(msg, str) and msg else "Request rejected"), (code if isinstance(code, str) else None)
    return "Request rejected", None


def _detail(resp: httpx.Response) -> str:
    return _parse_error(resp)[0]


class ApiClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 15.0,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = (base_url or os.environ.get("WEBINTELX_API_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.token, self.timeout = token, timeout
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)

    def _request(self, method: str, path: str, *, timeout: float | None = None, raw: bool = False, **kw: Any) -> Any:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            resp = self._client.request(method, path, headers=headers, timeout=timeout or self.timeout, **kw)
        except httpx.TimeoutException as exc:
            raise ApiError("backend_down", "The backend did not answer in time.") from exc
        except httpx.HTTPError as exc:
            raise ApiError("backend_down", f"Cannot reach the backend ({type(exc).__name__}).") from exc
        if resp.status_code >= 400:
            message, code = _parse_error(resp)
            raise ApiError(_kind(resp.status_code), message, resp.status_code, code)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.text if raw else resp.json()

    def get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params={k: v for k, v in params.items() if v is not None})

    def post(self, path: str, body: dict | None = None, timeout: float | None = None) -> Any:
        return self._request("POST", path, json=body or {}, timeout=timeout)

    # ---- auth / onboarding
    def register(self, email: str, password: str) -> dict:
        return self.post("/v1/auth/register", {"email": email, "password": password})

    def login(self, email: str, password: str) -> dict:
        res = self.post("/v1/auth/login", {"email": email, "password": password})
        self.token = res["access_token"]
        return res

    def logout(self) -> None:
        try:
            self.post("/v1/auth/logout")
        finally:
            self.token = None

    def websites(self) -> list[dict]:
        return self.get("/v1/websites")

    def create_website(self, domain: str) -> dict:
        return self.post("/v1/websites", {"domain": domain})

    def rotate_credential(self, website_id: str) -> dict:
        return self.post(f"/v1/websites/{website_id}/credentials/rotate")

    def revoke_credential(self, website_id: str, credential_id: str) -> dict:
        return self.post(f"/v1/websites/{website_id}/credentials/{credential_id}/revoke")

    def credentials(self, website_id: str) -> list[dict]:
        return self.get(f"/v1/websites/{website_id}/credentials")

    def sdk_snippet(self, website_id: str) -> dict:
        return self.get(f"/v1/websites/{website_id}/sdk-snippet")

    def verification(self, website_id: str) -> dict:
        return self.get(f"/v1/websites/{website_id}/verification")

    # ---- dashboard
    def events(self, website_id: str, limit: int = 20) -> list[dict]:
        return self.get(f"/v1/websites/{website_id}/events", limit=limit)

    def findings(self, website_id: str, limit: int = 500) -> list[dict]:
        return self.get(f"/v1/websites/{website_id}/findings", limit=limit)

    def sessions(self, website_id: str, suspicious_only: bool = True, limit: int = 10) -> list[dict]:
        return self.get(f"/v1/websites/{website_id}/sessions", suspicious_only=str(suspicious_only).lower(), sort="findings", limit=limit)

    def incidents(self, website_id: str) -> list[dict]:
        return self.get(f"/v1/websites/{website_id}/incidents", sort="risk")

    def alerts(self, website_id: str) -> dict:
        return self.get(f"/v1/websites/{website_id}/alerts")

    def load_demo(self, website_id: str, scenario: str = "hero_credential_abuse") -> dict:
        return self.post(f"/v1/websites/{website_id}/demo/load", {"scenario": scenario}, timeout=120)

    # ---- incident
    def incident(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}")

    def timeline(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/timeline")

    def graph(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/graph")

    def risk(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/risk")

    def threat_intel(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/threat-intel")

    def investigation(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/investigation")

    def recommendations(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/recommendations")

    def audit(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/audit")

    def investigate(self, incident_id: str) -> dict:
        """Runs anomaly -> TI -> risk -> LLM agents -> alert; allow a long timeout (free-tier LLM latency)."""
        return self.post(f"/v1/incidents/{incident_id}/investigate", timeout=180)

    # ---- M10: lifecycle, analyst feedback, recommendation decisions, report
    def lifecycle(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/lifecycle")

    def feedback(self, incident_id: str) -> dict:
        return self.get(f"/v1/incidents/{incident_id}/feedback")

    def post_feedback(self, incident_id: str, decision: str, comment: str | None = None) -> dict:
        return self.post(f"/v1/incidents/{incident_id}/feedback", {"decision": decision, "comment": comment})

    def set_status(self, incident_id: str, status: str, comment: str | None = None) -> dict:
        return self.post(f"/v1/incidents/{incident_id}/status", {"status": status, "comment": comment})

    def decide_recommendation(self, incident_id: str, action: str, decision: str, comment: str | None = None) -> dict:
        """Records a human decision only; the backend never executes a response action."""
        return self.post(f"/v1/incidents/{incident_id}/recommendations/{action}/decision", {"decision": decision, "comment": comment})

    def report(self, incident_id: str, fmt: str = "json") -> Any:
        """json -> dict; markdown / html -> str (generated on request by the backend from stored data)."""
        if fmt not in ("json", "markdown", "html"):
            raise ValueError("fmt must be json, markdown or html")
        return self._request("GET", f"/v1/incidents/{incident_id}/report", params={"format": fmt}, raw=fmt != "json")
