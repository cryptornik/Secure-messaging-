
import json
import re
import ssl
import secrets
import sqlite3
import base64
import binascii
from pathlib import Path
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHash,
    VerificationError,
    VerifyMismatchError,
)
from flask import Flask, g, jsonify, request

from server.database import get_connection, initialize_database

app = Flask(__name__)

# Limit incoming HTTP request bodies to 1 MB.
app.config["MAX_CONTENT_LENGTH"] = 1_000_000

password_hasher = PasswordHasher()

# In-memory sessions for the local demonstration.
# Restarting the server invalidates all existing tokens.
sessions = {}


def valid_username(username):
    return (
        isinstance(username, str)
        and re.fullmatch(r"[a-zA-Z0-9_]{3,32}", username) is not None
    )

def valid_public_key(value):
    if not isinstance(value, str) or not value:
        return False

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return False

    return len(decoded) == 32

def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")

        if scheme.lower() != "bearer" or not token:
            return jsonify(error="Authentication required."), 401

        username = sessions.get(token)
        if username is None:
            return jsonify(error="Invalid or expired session."), 401

        g.username = username
        return view(*args, **kwargs)

    return wrapped


def read_json():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


@app.post("/register")
def register():
    data = read_json()
    if data is None:
        return jsonify(error="A JSON object is required."), 400

    username = data.get("username")
    password = data.get("password")
    encryption_key = data.get("encryption_public_key")
    signing_key = data.get("signing_public_key")

    if not valid_username(username):
        return jsonify(
            error="Username must be 3-32 letters, digits, or underscores."
        ), 400

    if not isinstance(password, str) or len(password) < 12:
        return jsonify(error="Password must be at least 12 characters."), 400

       
    if not (
        valid_public_key(encryption_key)
        and valid_public_key(signing_key)
    ):
        return jsonify(error="Valid public keys are required."), 400

       

    password_hash = password_hasher.hash(password)

    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    username, password_hash,
                    encryption_public_key, signing_public_key
                ) VALUES (?, ?, ?, ?)
                """,
                (username, password_hash, encryption_key, signing_key),
            )
    except sqlite3.IntegrityError:
        return jsonify(error="Username already exists."), 409

    return jsonify(message="Registration successful."), 201


@app.post("/login")
def login():
    data = read_json()
    if data is None:
        return jsonify(error="A JSON object is required."), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Username and password are required."), 400

    with get_connection() as connection:
        user = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None:
        return jsonify(error="Invalid username or password."), 401

    try:
          
        password_hasher.verify(user["password_hash"], password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return jsonify(error="Invalid username or password."), 401

    token = secrets.token_urlsafe(32)
    sessions[token] = username

    return jsonify(token=token), 200


@app.get("/users/<username>/public-key")
@require_auth
def public_key(username):
    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT username, encryption_public_key, signing_public_key
            FROM users WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if user is None:
        return jsonify(error="User not found."), 404

    return jsonify(
        username=user["username"],
        encryption_public_key=user["encryption_public_key"],
        signing_public_key=user["signing_public_key"],
    )


@app.post("/messages")
@require_auth
def send_message():
    data = read_json()
    if data is None:
        return jsonify(error="A JSON object is required."), 400

    recipient = data.get("recipient")
    envelope = data.get("envelope")

    if not isinstance(recipient, str) or not isinstance(envelope, dict):
        return jsonify(error="Recipient and envelope are required."), 400

    if envelope.get("sender") != g.username:
        return jsonify(error="Envelope sender does not match login."), 400

    if envelope.get("recipient") != recipient:
        return jsonify(error="Envelope recipient does not match request."), 400

    if len(json.dumps(envelope)) > 100_000:
        return jsonify(error="Message envelope is too large."), 413

    with get_connection() as connection:
        sender = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (g.username,),
        ).fetchone()

        target = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (recipient,),
        ).fetchone()

        if target is None:
            return jsonify(error="Recipient not found."), 404

        cursor = connection.execute(
            """
            INSERT INTO messages (sender_id, recipient_id, envelope)
            VALUES (?, ?, ?)
            """,
            (sender["id"], target["id"], json.dumps(envelope)),
        )

        message_id = cursor.lastrowid

    return jsonify(message="Encrypted message queued.", id=message_id), 201


@app.get("/messages")
@require_auth
def receive_messages():
    # Fetch pending messages without changing their status.
    # The client acknowledges each message after successful decryption.
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (g.username,),
        ).fetchone()

        messages = connection.execute(
            """
            SELECT m.id, sender.username AS sender, m.envelope, m.created_at
            FROM messages AS m
            JOIN users AS sender ON sender.id = m.sender_id
            WHERE m.recipient_id = ? AND m.status = 'pending'
            ORDER BY m.id
            """,
            (user["id"],),
        ).fetchall()

    return jsonify(messages=[
        {
            "id": message["id"],
            "sender": message["sender"],
            "envelope": json.loads(message["envelope"]),
            "created_at": message["created_at"],
        }
        for message in messages
    ])


@app.post("/messages/<int:message_id>/ack")
@require_auth
def acknowledge_message(message_id):
    # Only the authenticated recipient can acknowledge the message.
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (g.username,),
        ).fetchone()

        cursor = connection.execute(
            """
            UPDATE messages
            SET status = 'delivered'
            WHERE id = ?
              AND recipient_id = ?
              AND status = 'pending'
            """,
            (message_id, user["id"]),
        )

        if cursor.rowcount == 1:
            return jsonify(
                message="Message acknowledged.",
                id=message_id,
                status="delivered",
            ), 200

        # Do not reveal whether another user's message exists.
        return jsonify(
            error="Pending message not found for this recipient."
        ), 404


@app.post("/logout")
@require_auth
def logout():
    header = request.headers.get("Authorization", "")
    token = header.partition(" ")[2]
    sessions.pop(token, None)
    return jsonify(message="Logged out.")


if __name__ == "__main__":
    initialize_database()

    project_root = Path(__file__).resolve().parent.parent

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(
        certfile=str(project_root / "certs" / "server.crt"),
        keyfile=str(project_root / "certs" / "server.key"),
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        ssl_context=tls_context,
    )