import os
import time
import sqlite3
import json
import pytest

from main import app, DB_FILENAME, ensure_db_and_table, get_db_conn, serialize_private_key_to_pem
from cryptography.hazmat.primitives.asymmetric import rsa

TEST_DB = DB_FILENAME


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """
    Use a temporary DB file for tests to avoid clobbering real DB.
    """
    db_file = tmp_path / "test_keys.db"
    monkeypatch.setenv("TEST_DB_PATH", str(db_file))
    # Monkeypatch the DB filename constant in the imported module
    import importlib
    import main as m
    m.DB_FILENAME = str(db_file)
    # Create DB and table
    ensure_db_and_table()
    yield
    # cleanup
    try:
        os.remove(str(db_file))
    except Exception:
        pass


def test_index():
    client = app.test_client()
    r = client.get("/")
    assert r.status_code == 200
    data = r.get_json()
    assert "JWKS server running" in data.get("msg", "")


def test_jwks_and_auth_endpoints():
    client = app.test_client()
    # Ensure DB has the two keys inserted by ensure_minimum_keys (called on import/run)
    from main import ensure_minimum_keys, list_keys, choose_key
    ensure_minimum_keys()
    rows = list_keys(filter_unexpired=False)
    assert len(rows) >= 2  # we expect at least two keys in DB

    # Request JWKS - should return at least one key (non-expired)
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    # At least one key should be non-expired
    assert any(int(k["kid"]) >= 1 for k in data["keys"])

    # Test POST /auth without expired param -> returned token
    payload = {"username": "userABC", "password": "password123"}
    r = client.post("/auth", json=payload)
    assert r.status_code == 200
    token = r.get_json().get("token")
    assert token is not None

    # Test POST /auth with expired param -> should return a token as well (signed by expired key)
    r2 = client.post("/auth?expired=1", json=payload)
    assert r2.status_code == 200
    token2 = r2.get_json().get("token")
    assert token2 is not None


def test_db_storage_roundtrip():
    # Directly insert a generated key, then retrieve it
    from main import store_private_key, choose_key
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = serialize_private_key_to_pem(priv)
    now = int(time.time())
    kid = store_private_key(pem, now + 3600)
    assert isinstance(kid, int)
    # choose a non-expired key should find it (maybe not the only one)
    chosen = choose_key(expired=False)
    assert chosen is not None
