
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_storage_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a storage-encryption key from a passphrase."""
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")

    return Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    ).derive(passphrase.encode("utf-8"))


def save_private_keys(identity: dict, passphrase: str, path: str) -> None:
    """Encrypt private keys before saving them to disk."""
    encryption_private = identity["encryption_private"].private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signing_private = identity["signing_private"].private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    private_data = json.dumps({
        "encryption_private": base64.b64encode(
            encryption_private
        ).decode("utf-8"),
        "signing_private": base64.b64encode(
            signing_private
        ).decode("utf-8"),
    }).encode("utf-8")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    storage_key = derive_storage_key(passphrase, salt)
    ciphertext = AESGCM(storage_key).encrypt(nonce, private_data, None)

    saved_data = {
        "version": 1,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file first, then replace the destination.
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(saved_data, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, destination)


def load_private_keys(path: str, passphrase: str) -> dict:
    """Load and decrypt private keys using the user's passphrase."""
    saved_data = json.loads(Path(path).read_text(encoding="utf-8"))

    if saved_data.get("version") != 1:
        raise ValueError("Unsupported private-key file version.")

    salt = base64.b64decode(saved_data["salt"], validate=True)
    nonce = base64.b64decode(saved_data["nonce"], validate=True)
    ciphertext = base64.b64decode(
        saved_data["ciphertext"], validate=True
    )

    storage_key = derive_storage_key(passphrase, salt)

    try:
        private_data = AESGCM(storage_key).decrypt(
            nonce, ciphertext, None
        )
    except InvalidTag as exc:
        raise ValueError(
            "Incorrect passphrase or damaged private-key file."
        ) from exc

    keys = json.loads(private_data.decode("utf-8"))

    return {
        "encryption_private": X25519PrivateKey.from_private_bytes(
            base64.b64decode(
                keys["encryption_private"], validate=True
            )
        ),
        "signing_private": Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(
                keys["signing_private"], validate=True
            )
        ),
    }
