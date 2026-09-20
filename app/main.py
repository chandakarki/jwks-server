import base64
import datetime
import uuid

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request

app = Flask(__name__)


def generate_key_pair(expired=False):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)
    expiry = now - datetime.timedelta(hours=1) if expired else now + datetime.timedelta(hours=1)
    return {"kid": kid, "private_key": private_key, "public_key": public_key, "expiry": expiry}


valid_key = generate_key_pair(expired=False)
expired_key = generate_key_pair(expired=True)
all_keys = [valid_key, expired_key]


def int_to_base64url(value):
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(key_entry):
    public_numbers = key_entry["public_key"].public_numbers()
    return {
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": key_entry["kid"],
        "n": int_to_base64url(public_numbers.n), "e": int_to_base64url(public_numbers.e),
    }


def key_to_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    now = datetime.datetime.now(datetime.timezone.utc)
    active_keys = [k for k in all_keys if k["expiry"] > now]
    return jsonify({"keys": [public_key_to_jwk(k) for k in active_keys]})


@app.route("/auth", methods=["POST"])
def auth():
    use_expired = "expired" in request.args
    key_entry = expired_key if use_expired else valid_key
    payload = {
        "sub": "fake-user",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": key_entry["expiry"],
    }
    token = pyjwt.encode(payload, key_to_pem(key_entry["private_key"]), algorithm="RS256",
                          headers={"kid": key_entry["kid"]})
    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
