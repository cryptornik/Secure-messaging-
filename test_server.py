
import base64
import pytest

from server.app import app, sessions
from server.database import initialize_database


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_file = tmp_path / "test_securechat.db"

    import server.database as database
    monkeypatch.setattr(database, "DATABASE_PATH", database_file)

    initialize_database()

    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client

    sessions.clear()



def register_user(client, username, password):
    return client.post(
        "/register",
        json={
            "username": username,
            "password": password,
            "encryption_public_key": base64.b64encode(
                b"E" * 32
            ).decode("ascii"),
            "signing_public_key": base64.b64encode(
                b"S" * 32
            ).decode("ascii"),
        },
    )


def login_user(client, username, password):
    response = client.post(
        "/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.get_json()["token"]


def test_registration_and_duplicate_username(client):
    response = register_user(client, "alice", "alice-password-123")
    assert response.status_code == 201

    duplicate = register_user(client, "alice", "another-password-123")
    assert duplicate.status_code == 409


def test_invalid_login_is_rejected(client):
    register_user(client, "alice", "alice-password-123")

    response = client.post(
        "/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_message_requires_authentication(client):
    response = client.get("/messages")
    assert response.status_code == 401


def test_authenticated_message_routing(client):
    register_user(client, "alice", "alice-password-123")
    register_user(client, "bob", "bob-password-123")

    alice_token = login_user(client, "alice", "alice-password-123")
    bob_token = login_user(client, "bob", "bob-password-123")

    envelope = {
        "version": 1,
        "sender": "alice",
        "recipient": "bob",
        "ciphertext": "example-encrypted-payload",
    }

    sent = client.post(
        "/messages",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"recipient": "bob", "envelope": envelope},
    )
    assert sent.status_code == 201

    inbox = client.get(
        "/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert inbox.status_code == 200

    messages = inbox.get_json()["messages"]
    assert len(messages) == 1
    assert messages[0]["sender"] == "alice"
    assert messages[0]["envelope"] == envelope

    
    # Messages remain pending until the recipient acknowledges them.
    second_inbox = client.get(
        "/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert second_inbox.status_code == 200
    assert len(second_inbox.get_json()["messages"]) == 1

    message_id = messages[0]["id"]

    acknowledged = client.post(
        f"/messages/{message_id}/ack",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert acknowledged.status_code == 200
    assert acknowledged.get_json()["status"] == "delivered"

    # Once acknowledged, the message should no longer be pending.
    third_inbox = client.get(
        "/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert third_inbox.status_code == 200
    assert third_inbox.get_json()["messages"] == []

def test_acknowledgement_requires_authentication(client):
    response = client.post("/messages/1/ack")

    assert response.status_code == 401

def test_only_recipient_can_acknowledge_message(client):
    register_user(client, "alice", "alice-password-123")
    register_user(client, "bob", "bob-password-123")

    alice_token = login_user(client, "alice", "alice-password-123")
    bob_token = login_user(client, "bob", "bob-password-123")

    envelope = {
        "version": 1,
        "sender": "alice",
        "recipient": "bob",
        "ciphertext": "example-encrypted-payload",
    }

    sent = client.post(
        "/messages",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"recipient": "bob", "envelope": envelope},
    )
    assert sent.status_code == 201

    inbox = client.get(
        "/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    message_id = inbox.get_json()["messages"][0]["id"]

    # Alice must not acknowledge a message addressed to Bob.
    response = client.post(
        f"/messages/{message_id}/ack",
        headers={"Authorization": f"Bearer {alice_token}"},
    )

    assert response.status_code == 404
