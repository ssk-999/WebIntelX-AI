from sqlalchemy.exc import OperationalError

from app.database import database
from app.database.models import Event, Incident
from app.main import app

EVT = {"event_type": "login_failure", "source": "auth", "session_id": "s1", "source_ip": "203.0.113.5",
       "endpoint": "/api/login?password=hunter2", "method": "POST", "status_code": 401,
       "attributes": {"password": "hunter2"}, "is_synthetic": True}


def ingest(client, key, events, **headers):
    return client.post("/v1/ingest", json={"events": events}, headers={"X-WebIntelX-Key": key, **headers})


def test_health_exposes_no_secrets(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["llm_configured"] is False
    assert "api_key" not in str(body).lower().replace("llm_configured", "")


def test_account_flow(client):
    assert client.post("/v1/auth/register", json={"email": "bad", "password": "longenough1"}).status_code == 422
    assert client.post("/v1/auth/register", json={"email": "u@x.com", "password": "short"}).status_code == 422
    h = {"Authorization": "Bearer nope"}
    assert client.get("/v1/auth/me", headers=h).status_code == 401
    client.post("/v1/auth/register", json={"email": "u@x.com", "password": "longenough1"})
    assert client.post("/v1/auth/register", json={"email": "U@x.com", "password": "longenough1"}).status_code == 409
    assert client.post("/v1/auth/login", json={"email": "u@x.com", "password": "wrongpass1"}).status_code == 401
    tok = client.post("/v1/auth/login", json={"email": "u@x.com", "password": "longenough1"}).json()["access_token"]
    auth = {"Authorization": f"Bearer {tok}"}
    assert client.get("/v1/auth/me", headers=auth).json()["email"] == "u@x.com"
    assert client.post("/v1/auth/logout", headers=auth).status_code == 204
    assert client.get("/v1/auth/me", headers=auth).status_code == 401


def test_website_and_credential(client, auth_a, site_a):
    assert site_a["credential"]["status"] == "active"
    assert site_a["ingestion_key"].startswith("wix_pk_")
    assert "key_hash" not in str(site_a)
    assert client.post("/v1/websites", json={"domain": "not a host!"}, headers=auth_a).status_code == 422
    creds = client.get(f"/v1/websites/{site_a['website']['website_id']}/credentials", headers=auth_a).json()
    assert len(creds) == 1 and "ingestion_key" not in creds[0]


def test_ingestion_verification_and_masking(client, auth_a, site_a):
    wid, key = site_a["website"]["website_id"], site_a["ingestion_key"]
    v = client.get(f"/v1/websites/{wid}/verification", headers=auth_a).json()
    assert v["status"] == "waiting_for_telemetry" and v["events_received"] == 0
    r = ingest(client, key, [EVT, {"event_type": "bogus"}])
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 1 and body["rejected"][0]["index"] == 1 and len(body["event_ids"]) == 1
    v = client.get(f"/v1/websites/{wid}/verification", headers=auth_a).json()
    assert v["status"] == "active" and v["events_received"] == 1
    ev = client.get(f"/v1/websites/{wid}/events", headers=auth_a).json()[0]
    assert ev["is_synthetic"] is True and "hunter2" not in str(ev)
    with database.SessionLocal() as db:
        row = db.get(Event, body["event_ids"][0])
        assert row.raw_data is None and "hunter2" not in str(row.processed_data)


def test_ingest_auth_failures(client, auth_a, site_a):
    assert client.post("/v1/ingest", json={"events": [EVT]}).status_code == 401
    assert ingest(client, "wix_pk_wrong", [EVT]).status_code == 401
    assert ingest(client, site_a["ingestion_key"], []).status_code == 422
    assert ingest(client, site_a["ingestion_key"], [EVT] * 21).status_code == 413


def test_origin_checks(client, site_a):
    key = site_a["ingestion_key"]
    assert ingest(client, key, [EVT], Origin="https://shop.example.com").status_code == 200
    assert ingest(client, key, [EVT], Origin="https://evil.example.net").status_code == 403
    assert ingest(client, key, [EVT]).status_code == 200  # server-side sender, no Origin


def test_rate_limit(client, site_a):
    key = site_a["ingestion_key"]
    codes = [ingest(client, key, [EVT] * 20).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_rotate_and_revoke(client, auth_a, site_a):
    wid, old = site_a["website"]["website_id"], site_a["ingestion_key"]
    new = client.post(f"/v1/websites/{wid}/credentials/rotate", headers=auth_a).json()
    assert ingest(client, old, [EVT]).status_code == 401
    assert ingest(client, new["ingestion_key"], [EVT]).status_code == 200
    cid = new["credential"]["credential_id"]
    assert client.post(f"/v1/websites/{wid}/credentials/{cid}/revoke", headers=auth_a).json()["status"] == "revoked"
    assert ingest(client, new["ingestion_key"], [EVT]).status_code == 401
    statuses = sorted(c["status"] for c in client.get(f"/v1/websites/{wid}/credentials", headers=auth_a).json())
    assert statuses == ["revoked", "rotated"]


def test_cross_customer_isolation(client, auth_a, auth_b, site_a):
    wid, key = site_a["website"]["website_id"], site_a["ingestion_key"]
    ingest(client, key, [EVT])
    with database.SessionLocal() as db:
        inc = Incident(website_id=wid, title="t")
        db.add(inc)
        db.commit()
        iid = inc.incident_id
    for path in (f"/v1/websites/{wid}", f"/v1/websites/{wid}/events", f"/v1/websites/{wid}/incidents",
                 f"/v1/websites/{wid}/verification", f"/v1/websites/{wid}/credentials"):
        assert client.get(path, headers=auth_b).status_code == 404, path
    assert client.post(f"/v1/websites/{wid}/credentials/rotate", headers=auth_b).status_code == 404
    assert client.get(f"/v1/incidents/{iid}", headers=auth_b).status_code == 404
    assert client.get(f"/v1/incidents/{iid}", headers=auth_a).status_code == 200
    assert client.get("/v1/websites", headers=auth_b).json() == []
    assert client.get(f"/v1/websites/{wid}/events", headers=auth_a).status_code == 200


def test_database_unavailable_returns_controlled_error(client, auth_a):
    def broken():
        raise OperationalError("SELECT 1", {}, Exception("db down"))
        yield  # pragma: no cover

    app.dependency_overrides[database.get_db] = broken
    try:
        r = client.post("/v1/auth/login", json={"email": "a@example.com", "password": "correct-horse-1"})
        assert r.status_code == 503 and r.json() == {"detail": "Database unavailable"}
    finally:
        app.dependency_overrides.clear()
