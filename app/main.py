import base64
import datetime
import sqlite3
import uuid
import time
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_NAME = "totally_not_my_privateKeys.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    conn.commit()
    conn.close()

init_db()

def generate_key_pair(expired=False):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)
    expiry = now - datetime.timedelta(hours=1) if expired else now + datetime.timedelta(hours=2)
    return {"kid": kid, "private_key": private_key, "public_key": public_key, "expiry": expiry}

def save_key_to_db(private_key, expiry):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem, int(expiry.timestamp()))
        )
        return cursor.lastrowid
    

def initialize_keys():
    now = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        valid_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp > ?",
            (now,)
        ).fetchone()[0]

        expired_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp <= ?",
            (now,)
        ).fetchone()[0]

    if valid_count == 0:
        valid_key = generate_key_pair(expired=False)
        save_key_to_db(
            valid_key["private_key"],
            valid_key["expiry"]
        )

    if expired_count == 0:
        expired_key = generate_key_pair(expired=True)
        save_key_to_db(
            expired_key["private_key"],
            expired_key["expiry"]
        )

def get_key_from_db(expired=False):
    now = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        if expired:
            row = conn.execute(
                "SELECT kid, key, exp FROM keys "
                "WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT kid, key, exp FROM keys "
                "WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()

    if row is None:
        return None

    kid, pem, expiry = row

    private_key = serialization.load_pem_private_key(
        pem,
        password=None
    )

    return {
        "kid": kid,
        "private_key": private_key,
        "expiry": expiry
    }

def save_key_to_db(private_key, expiry):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem, int(expiry.timestamp()))
        )
        return cursor.lastrowid

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





def get_valid_keys_from_db():
    now = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?",
            (now,)
        ).fetchall()

    valid_keys = []

    for kid, pem in rows:
        private_key = serialization.load_pem_private_key(
            pem,
            password=None
        )

        valid_keys.append({
            "kid": str(kid),
            "private_key": private_key,
            "public_key": private_key.public_key()
        })

    return valid_keys


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    active_keys = get_valid_keys_from_db()

    return jsonify({
        "keys": [public_key_to_jwk(k) for k in active_keys]
    })



@app.route("/auth", methods=["POST"])
def auth():
    use_expired = "expired" in request.args

    # Retrieve the appropriate RSA key from SQLite
    key_entry = get_key_from_db(expired=use_expired)

    if key_entry is None:
        return jsonify({"error": "No matching key found"}), 500

    # Create the JWT payload
    now = datetime.datetime.now(datetime.timezone.utc)

    payload = {
        "sub": "fake-user",
        "iat": now,
        "exp": key_entry["expiry"],
    }

    # Sign the JWT using the stored private key
    token = pyjwt.encode(
        payload,
        key_to_pem(key_entry["private_key"]),
        algorithm="RS256",
        headers={"kid": str(key_entry["kid"])}
    )

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
