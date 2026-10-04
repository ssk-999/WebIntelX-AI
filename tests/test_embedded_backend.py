"""M10 Part 2: single-process deployment helper (dashboard/embedded_backend.py). No real server and no Streamlit: the health probe, the launcher
and sleep are injected. Plain asserts, no pytest import."""
import threading

from dashboard import embedded_backend as eb


def _reset():
    eb._STATE.update({"thread": None, "port": None})


def _live_thread():
    stop = threading.Event()
    t = threading.Thread(target=stop.wait, daemon=True)
    t.start()
    return t, stop


def _dead_thread():
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
    return t


def test_is_truthy_and_port_parsing():
    assert all(eb.is_truthy(v) for v in ("true", "TRUE", " 1 ", "yes", "on")) and not any(eb.is_truthy(v) for v in (None, "", "false", "0", "no", "off"))
    assert eb.port_from({}) == 8000 and eb.port_from({"WEBINTELX_EMBEDDED_PORT": "8765"}) == 8765
    assert eb.port_from({"WEBINTELX_EMBEDDED_PORT": "abc"}) == 8000 and eb.port_from({"WEBINTELX_EMBEDDED_PORT": "99999"}) == 8000
    assert eb.local_url(8765) == "http://127.0.0.1:8765"


def test_bridge_secrets_copies_only_missing_top_level_strings_and_returns_names_only():
    env = {"GROQ_API_KEY": "already-set"}
    secrets = {"GROQ_API_KEY": "from-secrets", "PRIVACY_SALT": "salt-value", "EMPTY": "", "NESTED": {"a": "b"}, "NUMBER": 5}
    copied = eb.bridge_secrets(secrets, env)
    assert env == {"GROQ_API_KEY": "already-set", "PRIVACY_SALT": "salt-value"} and copied == ["PRIVACY_SALT"]
    assert "salt-value" not in copied


def test_ensure_started_reuses_a_backend_that_already_answers():
    _reset()
    launched = []
    res = eb.ensure_started(8000, health=lambda p: True, launcher=lambda p: launched.append(p), sleep=lambda s: None)
    assert res["status"] == "already_running" and launched == []


def test_ensure_started_launches_waits_for_health_and_is_idempotent():
    _reset()
    thread, stop = _live_thread()
    try:
        answers = iter([False, False, False, True])           # not running -> launched -> two probes fail -> healthy
        launches = []
        res = eb.ensure_started(8123, 5, health=lambda p: next(answers, True), launcher=lambda p: (launches.append(p) or thread), sleep=lambda s: None)
        assert res["status"] == "started" and launches == [8123] and res["url"] == "http://127.0.0.1:8123"
        again = eb.ensure_started(8123, 5, health=lambda p: True, launcher=lambda p: launches.append("second"), sleep=lambda s: None)
        assert again["status"] == "running" and launches == [8123]
    finally:
        stop.set()
        _reset()


def test_launcher_exception_becomes_a_failed_result_without_leaking_details():
    _reset()

    def boom(_port):
        raise RuntimeError("secret-looking detail /path/to/db")

    res = eb.ensure_started(8000, health=lambda p: False, launcher=boom, sleep=lambda s: None)
    assert res["status"] == "failed" and "RuntimeError" in res["message"] and "secret-looking" not in res["message"]
    _reset()


def test_server_that_dies_while_starting_is_reported_not_waited_for():
    _reset()
    sleeps = []
    res = eb.ensure_started(8000, 30, health=lambda p: False, launcher=lambda p: _dead_thread(), sleep=sleeps.append)
    assert res["status"] == "failed" and "stopped" in res["message"] and sleeps == []
    _reset()


def test_timeout_is_reported_when_the_backend_never_becomes_healthy():
    _reset()
    thread, stop = _live_thread()
    try:
        res = eb.ensure_started(8000, 1.0, health=lambda p: False, launcher=lambda p: thread, sleep=lambda s: None)
        assert res["status"] == "failed" and "did not become healthy" in res["message"]
    finally:
        stop.set()
        _reset()


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
