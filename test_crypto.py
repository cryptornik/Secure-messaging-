

import pytest

from client.crypto import (
    decrypt_message,
    encrypt_message,
    generate_identity,
    public_key_fingerprint,
)
from client.key_storage import load_private_keys, save_private_keys



def test_message_encrypts_and_decrypts():
    alice = generate_identity()
    bob = generate_identity()

    envelope = encrypt_message(
        plaintext="Hello Bob!",
        recipient_encryption_public=bob["encryption_public"],
        sender_signing_private=alice["signing_private"],
        sender_username="alice",
        recipient_username="bob",
    )

    # The envelope should not contain the plaintext.
    assert "Hello Bob!" not in str(envelope)

    plaintext = decrypt_message(
        envelope=envelope,
        recipient_encryption_private=bob["encryption_private"],
        sender_signing_public=alice["signing_public"],
        expected_sender="alice",
        expected_recipient="bob",
    )

    assert plaintext == "Hello Bob!"


def test_tampered_message_is_rejected():
    alice = generate_identity()
    bob = generate_identity()

    envelope = encrypt_message(
        plaintext="Original message",
        recipient_encryption_public=bob["encryption_public"],
        sender_signing_private=alice["signing_private"],
        sender_username="alice",
        recipient_username="bob",
    )

    envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"

    with pytest.raises(ValueError):
        decrypt_message(
            envelope=envelope,
            recipient_encryption_private=bob["encryption_private"],
            sender_signing_public=alice["signing_public"],
            expected_sender="alice",
            expected_recipient="bob",
        )

def test_private_keys_can_be_saved_and_loaded(tmp_path):
    identity = generate_identity()
    key_file = tmp_path / "private_keys.enc"

    save_private_keys(identity, "correct horse battery staple", str(key_file))

    loaded = load_private_keys(
        str(key_file), "correct horse battery staple"
    )

    assert (
        loaded["encryption_private"].private_bytes_raw()
        == identity["encryption_private"].private_bytes_raw()
    )
    assert (
        loaded["signing_private"].private_bytes_raw()
        == identity["signing_private"].private_bytes_raw()
    )


def test_wrong_passphrase_is_rejected(tmp_path):
    identity = generate_identity()
    key_file = tmp_path / "private_keys.enc"

    save_private_keys(identity, "correct passphrase", str(key_file))

    with pytest.raises(ValueError, match="Incorrect passphrase"):
        load_private_keys(str(key_file), "wrong passphrase")


def test_fingerprint_is_stable():
    alice = generate_identity()

    first = public_key_fingerprint(
        alice["encryption_public"],
        alice["signing_public"],
    )
    second = public_key_fingerprint(
        alice["encryption_public"],
        alice["signing_public"],
    )

    assert first == second
    assert len(first.replace(" ", "")) == 64


def test_fingerprint_changes_when_key_changes():
    alice = generate_identity()
    bob = generate_identity()

    alice_fingerprint = public_key_fingerprint(
        alice["encryption_public"],
        alice["signing_public"],
    )
    changed_fingerprint = public_key_fingerprint(
        bob["encryption_public"],
        alice["signing_public"],
    )

    assert alice_fingerprint != changed_fingerprint

import pytest

from cryptography.exceptions import InvalidTag
from client.crypto import (
    decrypt_message,
    encrypt_message,
    generate_identity,
)


def test_tampered_ciphertext_is_rejected():
    alice = generate_identity()
    bob = generate_identity()

    envelope = encrypt_message(
        plaintext="Secret message",
        recipient_encryption_public=bob["encryption_public"],
        sender_signing_private=alice["signing_private"],
        sender_username="alice",
        recipient_username="bob",
    )

    tampered = envelope.copy()
    tampered["ciphertext"] = (
        tampered["ciphertext"][:-2]
        + ("AA" if tampered["ciphertext"][-2:] != "AA" else "BB")
    )

    with pytest.raises((ValueError, InvalidTag)):
        decrypt_message(
            envelope=tampered,
            recipient_encryption_private=bob["encryption_private"],
            sender_signing_public=alice["signing_public"],
            expected_sender="alice",
            expected_recipient="bob",
        )

def test_invalid_signature_is_rejected():
    alice = generate_identity()
    bob = generate_identity()

    envelope = encrypt_message(
        plaintext="Secret message",
        recipient_encryption_public=bob["encryption_public"],
        sender_signing_private=alice["signing_private"],
        sender_username="alice",
        recipient_username="bob",
    )

    tampered = envelope.copy()
    tampered["signature"] = (
        "AAAA" if tampered["signature"] != "AAAA" else "BBBB"
    )

    from cryptography.exceptions import InvalidSignature

    with pytest.raises((ValueError, InvalidSignature)):
        decrypt_message(
            envelope=tampered,
            recipient_encryption_private=bob["encryption_private"],
            sender_signing_public=alice["signing_public"],
            expected_sender="alice",
            expected_recipient="bob",
        )
def test_wrong_recipient_is_rejected():
    alice = generate_identity()
    bob = generate_identity()
    charlie = generate_identity()

    envelope = encrypt_message(
        plaintext="Secret message",
        recipient_encryption_public=bob["encryption_public"],
        sender_signing_private=alice["signing_private"],
        sender_username="alice",
        recipient_username="bob",
    )

    with pytest.raises(ValueError):
        decrypt_message(
            envelope=envelope,
            recipient_encryption_private=charlie["encryption_private"],
            sender_signing_public=alice["signing_public"],
            expected_sender="alice",
            expected_recipient="charlie",
        )