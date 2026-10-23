
"""
Tests for the SQLite-backed JWKS server (Project 2).
"""

import datetime
import sqlite3
import time

import jwt as pyjwt
import pytest

import app.main as main


@pytest.fixture
def client():
    main.app.config["TESTING"] = True
    with main.app.test_client() as test_client:
        yield test_client


def get_database_keys():
    with sqlite3.connect(main.DB_NAME) as conn:
        return conn.execute(
            "SELECT kid, key, exp FROM keys"
        ).fetchall()


def test_database_exists():
    rows = get_database_keys()
    assert len(rows) >= 2


def test_database_has_valid_key():
    now = int(time.time())
    rows = get_database_keys()
    assert any(exp > now for kid, key, exp in rows)


def test_database_has_expired_key():
    now = int(time.time())
    rows = get_database_keys()
    assert any(exp <= now for kid, key, exp in rows)


def test_jwks_returns_200(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200


def test_jwks_contains_valid_key(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]
    now = int(time.time())

    rows = get_database_keys()
    valid_kids = [str(kid) for kid, key, exp in rows if exp > now]

    assert any(kid in kids for kid in valid_kids)


def test_jwks_excludes_expired_key(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]
    now = int(time.time())

    rows = get_database_keys()
    expired_kids = [str(kid) for kid, key, exp in rows if exp <= now]

    assert all(kid not in kids for kid in expired_kids)


def test_jwks_key_structure(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    assert len(data["keys"]) >= 1

    jwk = data["keys"][0]

    for field in ("kty", "use", "alg", "kid", "n", "e"):
        assert field in jwk

    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"


def test_auth_returns_200(client):
    response = client.post("/auth")
    assert response.status_code == 200


def test_auth_returns_token(client):
    response = client.post("/auth")
    data = response.get_json()

    assert "token" in data
    assert isinstance(data["token"], str)


def test_auth_token_uses_valid_kid(client):
    response = client.post("/auth")
    token = response.get_json()["token"]

    header = pyjwt.get_unverified_header(token)
    now = int(time.time())

    rows = get_database_keys()
    valid_kids = [str(kid) for kid, key, exp in rows if exp > now]

    assert header["kid"] in valid_kids


def test_auth_expired_returns_200(client):
    response = client.post("/auth?expired")
    assert response.status_code == 200


def test_auth_expired_uses_expired_kid(client):
    response = client.post("/auth?expired")
    token = response.get_json()["token"]

    header = pyjwt.get_unverified_header(token)
    now = int(time.time())

    rows = get_database_keys()
    expired_kids = [str(kid) for kid, key, exp in rows if exp <= now]

    assert header["kid"] in expired_kids


def test_auth_expired_token_is_actually_expired(client):
    response = client.post("/auth?expired")
    token = response.get_json()["token"]

    decoded = pyjwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False
        }
    )

    exp = datetime.datetime.fromtimestamp(
        decoded["exp"],
        tz=datetime.timezone.utc
    )

    now = datetime.datetime.now(datetime.timezone.utc)

    assert exp < now


def test_jwks_get_method_only(client):
    response = client.post("/.well-known/jwks.json")
    assert response.status_code == 405


def test_auth_post_method_only(client):
    response = client.get("/auth")
    assert response.status_code == 405


def test_get_valid_key_from_database():
    key = main.get_key_from_db(expired=False)

    assert key is not None
    assert key["expiry"] > int(time.time())


def test_get_expired_key_from_database():
    key = main.get_key_from_db(expired=True)

    assert key is not None
    assert key["expiry"] <= int(time.time())


def test_get_valid_keys_from_database():
    keys = main.get_valid_keys_from_db()

    assert len(keys) >= 1

    for key in keys:
        assert "kid" in key
        assert "private_key" in key
        assert "public_key" in key

def test_generate_valid_key_pair():
    key = main.generate_key_pair(expired=False)

    assert key["private_key"] is not None
    assert key["public_key"] is not None
    assert key["expiry"] > datetime.datetime.now(
        datetime.timezone.utc
    )


def test_generate_expired_key_pair():
    key = main.generate_key_pair(expired=True)

    assert key["private_key"] is not None
    assert key["public_key"] is not None
    assert key["expiry"] < datetime.datetime.now(
        datetime.timezone.utc
    )

def test_save_key_to_database(tmp_path, monkeypatch):
    test_db = tmp_path / "test_keys.db"
    monkeypatch.setattr(main, "DB_NAME", str(test_db))

    main.init_db()

    key = main.generate_key_pair(expired=False)

    kid = main.save_key_to_db(
        key["private_key"],
        key["expiry"]
    )

    with sqlite3.connect(test_db) as conn:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE kid = ?",
            (kid,)
        ).fetchone()

    assert row is not None
    assert row[0] == kid
    assert isinstance(row[1], bytes)
    assert row[2] > int(time.time())

def test_save_key_to_database(tmp_path, monkeypatch):
    test_db = tmp_path / "test_keys.db"
    monkeypatch.setattr(main, "DB_NAME", str(test_db))

    main.init_db()

    key = main.generate_key_pair(expired=False)

    kid = main.save_key_to_db(
        key["private_key"],
        key["expiry"]
    )

    with sqlite3.connect(test_db) as conn:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE kid = ?",
            (kid,)
        ).fetchone()

    assert row is not None
    assert row[0] == kid
    assert isinstance(row[1], bytes)
    assert row[2] > int(time.time())
