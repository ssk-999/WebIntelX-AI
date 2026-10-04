"""Optional single-process deployment (PRD section 41: "the backend and Streamlit frontend may be deployed together for the hackathon ...
provided the architecture remains modular").

Streamlit Community Cloud runs one Streamlit process and cannot host a separate FastAPI service. When `WEBINTELX_EMBEDDED_BACKEND=true`
(environment variable or Streamlit secret) the dashboard starts the unchanged FastAPI app (`app.main:app`) in a daemon thread of the SAME process,
bound to 127.0.0.1 only, and talks to it over HTTP exactly as it would talk to a remote backend. The dashboard still never opens the database.

PRD does not specify this; using the following implementation assumptions:
  * Local-only bind: the embedded backend is NOT reachable from the internet, so a customer website's browser SDK cannot send telemetry to it.
    It is meant for the synthetic demo loader. For real SDK telemetry deploy the backend separately (Dockerfile) and set WEBINTELX_API_URL.
  * Streamlit Community Cloud's file system is not guaranteed to persist: the SQLite database may reset when the app restarts.
  * Top-level string secrets are copied into the process environment (never overwriting a variable that is already set) BEFORE the backend
    settings are read, so GROQ_API_KEY / PRIVACY_SALT / TI_PROVIDER ... set as Streamlit secrets reach the backend. Secret values are never logged.
Everything here is plain Python with injectable dependencies so it can be unit-tested without Streamlit or a real server.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import urllib.request
from typing import Any, Callable, Mapping, MutableMapping

log = logging.getLogger("webintelx.embedded")

DEFAULT_PORT = 8000
_TRUE = ("1", "true", "yes", "on")
_LOCK = threading.Lock()
_STATE: dict[str, Any] = {"thread": None, "port": None}


def is_truthy(value: Any) -> bool:
    return str(value if value is not None else "").strip().lower() in _TRUE


def port_from(env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    try:
        port = int(env.get("WEBINTELX_EMBEDDED_PORT", DEFAULT_PORT))
    except (TypeError, ValueError):
        return DEFAULT_PORT
    return port if 1 <= port <= 65535 else DEFAULT_PORT


def local_url(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def bridge_secrets(secrets: Mapping[str, Any], env: MutableMapping[str, str]) -> list[str]:
    """Copy top-level, non-empty string secrets into `env` unless the variable is already set. Returns the NAMES copied (never values)."""
    copied: list[str] = []
    for key in list(secrets):
        value = secrets[key]
        if isinstance(key, str) and isinstance(value, str) and value and not env.get(key):
            env[key] = value
            copied.append(key)
    return copied


def _health(port: int, timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(f"{local_url(port)}/health", timeout=timeout) as resp:      # fixed loopback URL, not user-controlled
            return resp.status == 200
    except Exception:  # noqa: BLE001 - not up (yet)
        return False


def _default_launcher(port: int) -> threading.Thread:
    """Starts the real FastAPI app with uvicorn in a daemon thread (imports are lazy: only needed in embedded mode)."""
    import uvicorn

    from app.main import app

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, name="webintelx-embedded-backend", daemon=True)
    thread.start()
    return thread


def ensure_started(port: int = DEFAULT_PORT, wait_seconds: float = 30.0, *, health: Callable[[int], bool] = _health,
                   launcher: Callable[[int], threading.Thread] = _default_launcher, sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Idempotent. Returns {"status": "running" | "already_running" | "started" | "failed", "url": ..., "message": ...}. Never raises."""
    url = local_url(port)
    with _LOCK:
        thread = _STATE.get("thread")
        if thread is not None and thread.is_alive() and _STATE.get("port") == port and health(port):
            return {"status": "running", "url": url, "message": "Embedded backend is running."}
        if health(port):
            return {"status": "already_running", "url": url, "message": f"A backend already answers on {url}; using it."}
        try:
            thread = launcher(port)
        except Exception as exc:  # noqa: BLE001 - import or bind problems must become a visible dashboard error, not a crash
            log.error("embedded backend could not start: %s", type(exc).__name__)
            return {"status": "failed", "url": url, "message": f"The embedded backend could not start ({type(exc).__name__}). Check the application logs."}
        _STATE["thread"], _STATE["port"] = thread, port
        waited, step = 0.0, 0.25
        while waited <= wait_seconds:
            if health(port):
                return {"status": "started", "url": url, "message": "Embedded backend started."}
            if not thread.is_alive():
                return {"status": "failed", "url": url, "message": "The embedded backend stopped while starting (is the port already in use?). Check the application logs."}
            sleep(step)
            waited += step
    return {"status": "failed", "url": url, "message": f"The embedded backend did not become healthy within {wait_seconds:g} seconds."}
