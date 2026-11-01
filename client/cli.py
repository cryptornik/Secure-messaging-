
import base64
import getpass
import json
from pathlib import Path

import requests

from client.crypto import (
    decrypt_message,
    encrypt_message,
    export_public_bundle,
    generate_identity,
    public_key_fingerprint,
    raw_public_key,
)
from client.key_storage import load_private_keys, save_private_keys


SERVER = "http://127.0.0.1:5000"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# --------------------------------------------------
# API COMMUNICATION
# --------------------------------------------------

def api_request(method, endpoint, token=None, payload=None):
    headers = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.request(
            method,
            f"{SERVER}{endpoint}",
            headers=headers,
            json=payload,
            timeout=10,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not connect to server: {exc}") from exc

    try:
        result = response.json()
    except ValueError:
        result = {}

    if not response.ok:
        error = result.get("error", f"Server error: {response.status_code}")
        raise RuntimeError(error)

    return result


# --------------------------------------------------
# FINGERPRINT TRUST MANAGEMENT
# --------------------------------------------------

def trusted_fingerprints_path(username):
    user_dir = DATA_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir / "trusted_fingerprints.json"


def load_trusted_fingerprints(username):
    path = trusted_fingerprints_path(username)

    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            trusted = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read trusted fingerprints: {exc}") from exc

    if not isinstance(trusted, dict):
        raise RuntimeError("Trusted fingerprints file has an invalid format.")

    return trusted


def save_trusted_fingerprint(username, contact, fingerprint):
    trusted = load_trusted_fingerprints(username)
    trusted[contact] = fingerprint

    path = trusted_fingerprints_path(username)

    with path.open("w", encoding="utf-8") as file:
        json.dump(trusted, file, indent=4)


def verify_trusted_fingerprint(username, contact, fingerprint):
    trusted = load_trusted_fingerprints(username)
    saved_fingerprint = trusted.get(contact)

    if saved_fingerprint is None:
        return "unknown"

    if saved_fingerprint != fingerprint:
        return "mismatch"

    return "trusted"


def fingerprint_from_private_keys(private_keys):
    encryption_public = private_keys["encryption_private"].public_key()
    signing_public = private_keys["signing_private"].public_key()

    return public_key_fingerprint(
        raw_public_key(encryption_public),
        raw_public_key(signing_public),
    )


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

def register():
    print("\n=== Register ===")

    username = input("Choose a username: ").strip().lower()

    if not username:
        print("Username cannot be empty.")
        return

    password = getpass.getpass(
        "Choose a password (at least 12 characters): "
    )
    confirmation = getpass.getpass("Confirm password: ")

    if password != confirmation:
        print("Passwords do not match.")
        return

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    key_file = DATA_DIR / username / "private_keys.enc"

    if key_file.exists():
        print("A local key file already exists for this username.")
        print("Log in or back up your keys instead of overwriting them.")
        return

    try:
        identity = generate_identity()
        public_bundle = export_public_bundle(identity)

        api_request(
            "POST",
            "/register",
            payload={
                "username": username,
                "password": password,
                **public_bundle,
            },
        )

        save_private_keys(identity, password, str(key_file))

        print(f"Account '{username}' registered.")
        print(f"Private keys saved locally: {key_file}")
        print("\nYour public-key fingerprint:")
        print(fingerprint_from_private_keys(identity))
        print("Verify fingerprints through a trusted separate channel.")

    except (
        RuntimeError,
        requests.RequestException,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"Registration failed: {exc}")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

def login():
    print("\n=== Login ===")

    username = input("Username: ").strip().lower()
    password = getpass.getpass("Password: ")

    key_file = DATA_DIR / username / "private_keys.enc"
    token = None

    try:
        token_result = api_request(
            "POST",
            "/login",
            payload={
                "username": username,
                "password": password,
            },
        )

        token = token_result["token"]

        if not key_file.exists():
            print("Local private-key file not found. Cannot decrypt messages.")
            print("Do not generate replacement keys for an existing account.")
            api_request("POST", "/logout", token=token)
            return

        private_keys = load_private_keys(str(key_file), password)

        print(f"Logged in as {username}.")
        print("\nYour public-key fingerprint:")
        print(fingerprint_from_private_keys(private_keys))
        print("Compare this fingerprint through a trusted separate channel.")

        while True:
            print("\n1. Send message")
            print("2. Check inbox")
            print("3. Logout")

            choice = input("Choose an option: ").strip()

            if choice == "1":
                send_message(username, token, private_keys)
            elif choice == "2":
                check_inbox(username, token, private_keys)
            elif choice == "3":
                try:
                    api_request("POST", "/logout", token=token)
                except RuntimeError as exc:
                    print(f"Logout request failed: {exc}")

                print("Logged out.")
                break
            else:
                print("Invalid option.")

    except (
        RuntimeError,
        requests.RequestException,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"Login failed: {exc}")

        # Clean up a session if login succeeded but local key loading failed.
        if token:
            try:
                api_request("POST", "/logout", token=token)
            except RuntimeError:
                pass


# --------------------------------------------------
# SEND MESSAGE
# --------------------------------------------------

def send_message(username, token, private_keys):
    recipient = input("Recipient username: ").strip().lower()
    plaintext = input("Message: ")

    if not recipient:
        print("Recipient username cannot be empty.")
        return

    if not plaintext:
        print("Message cannot be empty.")
        return

    if recipient == username:
        print("Sending messages to yourself is not supported.")
        return

    try:
        public_data = api_request(
            "GET",
            f"/users/{recipient}/public-key",
            token=token,
        )

        recipient_public = base64.b64decode(
            public_data["encryption_public_key"],
            validate=True,
        )
        recipient_signing_public = base64.b64decode(
            public_data["signing_public_key"],
            validate=True,
        )

        recipient_fingerprint = public_key_fingerprint(
            recipient_public,
            recipient_signing_public,
        )

        print(f"\nFingerprint for {recipient}:")
        print(recipient_fingerprint)

        trust_status = verify_trusted_fingerprint(
            username,
            recipient,
            recipient_fingerprint,
        )

        if trust_status == "unknown":
            print(f"No trusted fingerprint saved for {recipient}.")
            print("Verify it with the recipient through a trusted, separate channel.")

            confirmation = input(
                f"Have you independently verified {recipient}'s "
                "fingerprint? (yes/no): "
            ).strip().lower()

            if confirmation != "yes":
                print("Message cancelled. Fingerprint not trusted.")
                return

            save_trusted_fingerprint(
                username,
                recipient,
                recipient_fingerprint,
            )
            print(f"Fingerprint for {recipient} saved as trusted.")

        elif trust_status == "mismatch":
            saved_fingerprint = load_trusted_fingerprints(username)[recipient]

            print("\nWARNING: The trusted fingerprint has changed!")
            print(f"Previously trusted: {saved_fingerprint}")
            print(f"Currently received: {recipient_fingerprint}")
            print("Message cancelled. Verify the change independently.")
            return

        else:
            print(f"Fingerprint for {recipient} matches the saved value.")

        envelope = encrypt_message(
            plaintext=plaintext,
            recipient_encryption_public=recipient_public,
            sender_signing_private=private_keys["signing_private"],
            sender_username=username,
            recipient_username=recipient,
        )

        result = api_request(
            "POST",
            "/messages",
            token=token,
            payload={
                "recipient": recipient,
                "envelope": envelope,
            },
        )

        print(f"Message queued successfully. ID: {result['id']}")

    except (
        RuntimeError,
        requests.RequestException,
        ValueError,
        KeyError,
        OSError,
    ) as exc:
        print(f"Could not send message: {exc}")


# --------------------------------------------------
# CHECK INBOX
# --------------------------------------------------

def check_inbox(username, token, private_keys):
    try:
        result = api_request("GET", "/messages", token=token)
        messages = result.get("messages", [])

        if not messages:
            print("Your inbox is empty.")
            return

        print(f"\n=== Inbox: {len(messages)} message(s) ===")

        for message in messages:
            sender = message.get("sender", "unknown")
            message_id = message.get("id", "unknown")
            envelope = message.get("envelope")

            print(f"\nMessage ID: {message_id}")
            print(f"From: {sender}")

            try:
                if not isinstance(envelope, dict):
                    print("Message rejected: invalid envelope.")
                    continue

                sender_data = api_request(
                    "GET",
                    f"/users/{sender}/public-key",
                    token=token,
                )

                sender_encryption_public = base64.b64decode(
                    sender_data["encryption_public_key"],
                    validate=True,
                )
                sender_signing_public = base64.b64decode(
                    sender_data["signing_public_key"],
                    validate=True,
                )

                sender_fingerprint = public_key_fingerprint(
                    sender_encryption_public,
                    sender_signing_public,
                )

                trust_status = verify_trusted_fingerprint(
                    username,
                    sender,
                    sender_fingerprint,
                )

                if trust_status == "unknown":
                    print(f"No trusted fingerprint saved for {sender}.")
                    print(f"Fingerprint: {sender_fingerprint}")
                    print(
                        "Verify it with the sender through a trusted, "
                        "separate channel."
                    )

                    confirmation = input(
                        f"Have you independently verified {sender}'s "
                        "fingerprint? (yes/no): "
                    ).strip().lower()

                    if confirmation != "yes":
                        print("Message rejected: fingerprint not verified.")
                        continue

                    save_trusted_fingerprint(
                        username,
                        sender,
                        sender_fingerprint,
                    )
                    print(f"Fingerprint for {sender} saved as trusted.")

                elif trust_status == "mismatch":
                    saved_fingerprint = load_trusted_fingerprints(
                        username
                    )[sender]

                    print("WARNING: Sender fingerprint has changed!")
                    print(f"Previously trusted: {saved_fingerprint}")
                    print(f"Currently received: {sender_fingerprint}")
                    print(
                        "Message rejected. Verify the change independently."
                    )
                    continue

                
                plaintext = decrypt_message(
                    envelope=envelope,
                    recipient_encryption_private=(
                        private_keys["encryption_private"]
                    ),
                    sender_signing_public=sender_signing_public,
                    expected_sender=sender,
                    expected_recipient=username,
                )

                api_request(
                    "POST",
                    f"/messages/{message_id}/ack",
                    token=token,
                )

                print(f"Decrypted message from {sender}: {plaintext}")


            except (
                RuntimeError,
                requests.RequestException,
                ValueError,
                KeyError,
            ) as exc:
                print(f"Could not verify/decrypt message {message_id}: {exc}")

    except (
        RuntimeError,
        requests.RequestException,
        ValueError,
    ) as exc:
        print(f"Could not retrieve inbox: {exc}")


# --------------------------------------------------
# MAIN MENU
# --------------------------------------------------

def main():
    while True:
        print("\n=== SecureChatCLI ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting SecureChatCLI.")
