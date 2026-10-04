import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="wix_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["PRIVACY_SALT"] = "test-salt"
os.environ["IP_PRIVACY_MODE"] = "none"
os.environ["INGEST_RATE_LIMIT_PER_MIN"] = "50"
os.environ["INGEST_MAX_BATCH_SIZE"] = "20"
os.environ["GROQ_API_KEY"] = ""

import pytest
from fastapi.testclient import TestClient

from app.database import database
from app.main import app
from app.security import ingest_limiter, login_limiter


@pytest.fixture(autouse=True)
def fresh_db():
    database.Base.metadata.drop_all(bind=database.engine)
    database.init_db()
    ingest_limiter.reset()
    login_limiter.reset()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _register_login(client, email):
    assert client.post("/v1/auth/register", json={"email": email, "password": "correct-horse-1"}).status_code == 201
    r = client.post("/v1/auth/login", json={"email": email, "password": "correct-horse-1"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def auth_a(client):
    return _register_login(client, "a@example.com")


@pytest.fixture
def auth_b(client):
    return _register_login(client, "b@example.com")


@pytest.fixture
def site_a(client, auth_a):
    r = client.post("/v1/websites", json={"domain": "shop.example.com"}, headers=auth_a)
    assert r.status_code == 201
    return r.json()
