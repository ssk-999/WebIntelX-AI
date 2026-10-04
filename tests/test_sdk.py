import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "sdk" / "sdk_harness.js"
SDK = ROOT / "sdk" / "web-intelx-ai.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is required for SDK tests")


def run_sdk(scenario: str) -> dict:
    out = subprocess.run(["node", str(HARNESS), str(SDK), scenario], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_happy_path_payload_shape_and_privacy():
    d = run_sdk("happy")
    assert d["headers"]["X-WebIntelX-Key"] == "wix_pk_testkey" and d["credentials"] == "omit"
    types = [e["event_type"] for e in d["events"]]
    assert types == ["page_view", "interaction", "page_view"]
    assert d["events"][0]["endpoint"] == "/checkout"           # query string dropped by default
    assert "token" not in json.dumps(d["events"]) and "4111" not in json.dumps(d["events"])
    assert d["events"][1]["attributes"]["clicks"] == 2 and d["events"][1]["attributes"]["key_events"] == 1
    assert "key" not in d["events"][1]["attributes"]            # key identity is never collected
    assert d["api"] == ["__loaded", "version", "flush", "identify"]


def test_query_string_is_opt_in():
    d = run_sdk("include_query")
    assert d["events"][0]["endpoint"] == "/checkout?token=abc&x=1"


@pytest.mark.parametrize("scenario", ["fetch_rejects", "fetch_throws", "storage_blocked"])
def test_sdk_never_throws_into_host_page(scenario):
    assert run_sdk(scenario)["threw"] is False


def test_storage_blocked_still_collects():
    d = run_sdk("storage_blocked")
    assert [e["event_type"] for e in d["events"]] == ["page_view"]


def test_circuit_breaker_stops_sending_after_repeated_failures():
    d = run_sdk("breaker")
    assert 1 <= d["sent"] <= 5


def test_placeholder_key_disables_sdk_and_double_load_is_idempotent():
    d = run_sdk("placeholder_key")
    assert d == {"loaded": False, "sent": 0}
    assert len(run_sdk("double_load")["events"]) == 1


def test_sdk_payload_is_accepted_by_ingestion_api(client, auth_a, site_a):
    """Contract test: what the real SDK emits must validate against the backend schema."""
    payload = run_sdk("happy")["events"]
    r = client.post("/v1/ingest", json={"events": payload}, headers={"X-WebIntelX-Key": site_a["ingestion_key"],
                                                                      "Origin": "https://shop.example.com"})
    assert r.status_code == 200
    assert r.json()["accepted"] == len(payload) and r.json()["rejected"] == []
    wid = site_a["website"]["website_id"]
    stored = client.get(f"/v1/websites/{wid}/events", headers=auth_a).json()
    assert len(stored) == len(payload) and all(e["source"] == "sdk" and e["source_ip"] is None for e in stored)
    assert client.get(f"/v1/websites/{wid}/verification", headers=auth_a).json()["status"] == "active"


def test_snippet_has_integrity_and_no_server_secret(client, auth_a, site_a):
    snip = site_a["sdk_snippet"]
    assert 'integrity="sha384-' in snip and f'data-key="{site_a["ingestion_key"]}"' in snip and "defer" in snip
    wid = site_a["website"]["website_id"]
    again = client.get(f"/v1/websites/{wid}/sdk-snippet", headers=auth_a).json()
    assert "YOUR_INGESTION_KEY" in again["snippet"] and site_a["ingestion_key"] not in json.dumps(again)
    served = client.get("/sdk/web-intelx-ai.js")
    assert served.status_code == 200 and "javascript" in served.headers["content-type"]
    assert served.content == SDK.read_bytes()
    import base64, hashlib
    digest = "sha384-" + base64.b64encode(hashlib.sha384(served.content).digest()).decode()
    assert digest in snip
    # rotation returns a fresh snippet carrying the new key
    rot = client.post(f"/v1/websites/{wid}/credentials/rotate", headers=auth_a).json()
    assert rot["ingestion_key"] in rot["sdk_snippet"]
    # other customers cannot fetch it
    assert client.get(f"/v1/websites/{wid}/sdk-snippet").status_code == 401


def test_sdk_contains_no_high_privilege_secret_patterns():
    src = SDK.read_text()
    for needle in ("GROQ", "TI_API_KEY", "password_hash", "Authorization"):
        assert needle not in src
