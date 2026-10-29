import hashlib
import hmac
import os
import re
import sqlite3

from database import connect_db

ITERATIONS = 600_000
SALT_BYTES = 16
HASH_BYTES = 32


def validate_username(username):
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return None
    return username


def _derive_hash(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=HASH_BYTES,
    )


def register_user(username, password):
    username = validate_username(username)
    if username is None:
        return False, "Invalid username. Use 3–32 letters, numbers, dots, underscores, or hyphens."
    if len(password) < 12:
        return False, "Password must be at least 12 characters."

    salt = os.urandom(SALT_BYTES)
    hashed = _derive_hash(password, salt)

    try:
        with connect_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, hashed),
            )
        return True, "Registration successful."
    except sqlite3.IntegrityError:
        return False, "That username is already registered."


def authenticate_user(username, password):
    with connect_db() as conn:
        row = conn.execute(
            "SELECT id, username, password_salt, password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if row is None:
        return False, None

    user_id, saved_username, salt, saved_hash = row
    candidate_hash = _derive_hash(password, salt)

    if hmac.compare_digest(candidate_hash, saved_hash):
        return True, {"id": user_id, "username": saved_username}
    return False, None
