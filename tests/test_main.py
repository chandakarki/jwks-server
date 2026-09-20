"""
Tests for the JWKS server.

Covers:
  - /auth returns a valid signed JWT
  - /auth?expired returns a JWT signed with the expired key
  - JWKS endpoint returns the valid key
  - JWKS endpoint excludes the expired key
  - JWKS response has correct JWK structure
"""

import datetime

import jwt as pyjwt
import pytest

from app.main import app, valid_key, expired_key


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_jwks_returns_200(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200


def test_jwks_contains_valid_key(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()
    kids = [key["kid"] for key in data["keys"]]
    assert valid_key["kid"] in kids


def test_jwks_excludes_expired_key(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()
    kids = [key["kid"] for key in data["keys"]]
    assert expired_key["kid"] not in kids


def test_jwks_key_structure(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()
    assert len(data["keys"]) == 1
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
    assert header["kid"] == valid_key["kid"]


def test_auth_expired_returns_200(client):
    response = client.post("/auth?expired")
    assert response.status_code == 200


def test_auth_expired_uses_expired_kid(client):
    response = client.post("/auth?expired")
    token = response.get_json()["token"]
    header = pyjwt.get_unverified_header(token)
    assert header["kid"] == expired_key["kid"]


def test_auth_expired_token_is_actually_expired(client):
    response = client.post("/auth?expired")
    token = response.get_json()["token"]
    decoded = pyjwt.decode(token, options={"verify_signature": False})
    exp = datetime.datetime.fromtimestamp(decoded["exp"], tz=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert exp < now


def test_jwks_get_method_only(client):
    response = client.post("/.well-known/jwks.json")
    assert response.status_code == 405


def test_auth_post_method_only(client):
    response = client.get("/auth")
    assert response.status_code == 405
