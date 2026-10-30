
import base64
import json
import os
import hashlib

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encode_bytes(data: bytes) -> str:
    """Convert bytes to a Base64 string."""
    return base64.b64encode(data).decode("utf-8")


def decode_bytes(data: str) -> bytes:
    """Convert a Base64 string back to bytes."""
    return base64.b64decode(data, validate=True)


def raw_public_key(key) -> bytes:
    """Export a public key in raw byte format."""
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def generate_identity():
    """Generate separate keys for encryption key agreement and signatures."""
    encryption_private = X25519PrivateKey.generate()
    signing_private = Ed25519PrivateKey.generate()

    identity = {
        "encryption_private": encryption_private,
        "signing_private": signing_private,
        "encryption_public": raw_public_key(encryption_private.public_key()),
        "signing_public": raw_public_key(signing_private.public_key()),
    }

    return identity


def derive_message_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"SecureChatCLI message encryption v1",
    ).derive(shared_secret)


def encrypt_message(
    plaintext: str,
    recipient_encryption_public: bytes,
    sender_signing_private: Ed25519PrivateKey,
    sender_username: str,
    recipient_username: str,
) -> dict:
    """Encrypt a message and sign its envelope."""
    ephemeral_private = X25519PrivateKey.generate()
    recipient_public = X25519PublicKey.from_public_bytes(
        recipient_encryption_public
    )

    shared_secret = ephemeral_private.exchange(recipient_public)
    salt = os.urandom(16)
    message_key = derive_message_key(shared_secret, salt)

    nonce = os.urandom(12)
    aad = json.dumps(
        {
            "sender": sender_username,
            "recipient": recipient_username,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    ciphertext = AESGCM(message_key).encrypt(
        nonce, plaintext.encode("utf-8"), aad
    )

    envelope = {
        "version": 1,
        "sender": sender_username,
        "recipient": recipient_username,
        "ephemeral_public": encode_bytes(
            raw_public_key(ephemeral_private.public_key())
        ),
        "salt": encode_bytes(salt),
        "nonce": encode_bytes(nonce),
        "ciphertext": encode_bytes(ciphertext),
    }

    signed_data = json.dumps(
        envelope, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    signature = sender_signing_private.sign(signed_data)
    envelope["signature"] = encode_bytes(signature)

    return envelope


def decrypt_message(
    envelope: dict,
    recipient_encryption_private: X25519PrivateKey,
    sender_signing_public: bytes,
    expected_sender: str,
    expected_recipient: str,
) -> str:
    """Verify the sender's signature, then decrypt and authenticate."""
    if envelope.get("version") != 1:
        raise ValueError("Unsupported message version.")

    if envelope.get("sender") != expected_sender:
        raise ValueError("Unexpected sender.")

    if envelope.get("recipient") != expected_recipient:
        raise ValueError("Unexpected recipient.")

    unsigned_envelope = {
        key: value for key, value in envelope.items() if key != "signature"
    }
    signed_data = json.dumps(
        unsigned_envelope, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    try:
        Ed25519PublicKey.from_public_bytes(sender_signing_public).verify(
            decode_bytes(envelope["signature"]), signed_data
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise ValueError("Message signature verification failed.") from exc

    ephemeral_public = X25519PublicKey.from_public_bytes(
        decode_bytes(envelope["ephemeral_public"])
    )
    shared_secret = recipient_encryption_private.exchange(ephemeral_public)

    message_key = derive_message_key(
        shared_secret, decode_bytes(envelope["salt"])
    )

    aad = json.dumps(
        {
            "sender": expected_sender,
            "recipient": expected_recipient,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        plaintext = AESGCM(message_key).decrypt(
            decode_bytes(envelope["nonce"]),
            decode_bytes(envelope["ciphertext"]),
            aad,
        )
    except (InvalidTag, ValueError) as exc:
        raise ValueError("Message decryption or authentication failed.") from exc

    return plaintext.decode("utf-8")

def export_public_bundle(identity: dict) -> dict:
    """Return public keys in a format suitable for the API."""
    return {
        "encryption_public_key": encode_bytes(
            identity["encryption_public"]
        ),
        "signing_public_key": encode_bytes(
            identity["signing_public"]
        ),
    }

def public_key_fingerprint(
    encryption_public: bytes,
    signing_public: bytes,
) -> str:
    """Create a fingerprint for comparing public keys out of band."""
    combined = (
        b"SecureChatCLI fingerprint v1"
        + encryption_public
        + signing_public
    )

    digest = hashlib.sha256(combined).hexdigest().upper()

    # Group the fingerprint into readable blocks.
    return " ".join(
        digest[index:index + 4]
        for index in range(0, len(digest), 4)
    )
