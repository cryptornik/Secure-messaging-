
import pytest

from client.cli import (
    save_trusted_fingerprint,
    verify_trusted_fingerprint,
)
from client.crypto import generate_identity
from client.key_storage import save_private_keys, load_private_keys


def test_unknown_fingerprint_is_not_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "client.cli.trusted_fingerprints_path",
        lambda username: tmp_path / "trusted_fingerprints.json",
    )

    assert verify_trusted_fingerprint(
        "alice", "bob", "AAAA"
    ) == "unknown"


def test_changed_fingerprint_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "client.cli.trusted_fingerprints_path",
        lambda username: tmp_path / "trusted_fingerprints.json",
    )

    save_trusted_fingerprint("alice", "bob", "AAAA")

    assert verify_trusted_fingerprint(
        "alice", "bob", "BBBB"
    ) == "mismatch"


def test_matching_fingerprint_is_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "client.cli.trusted_fingerprints_path",
        lambda username: tmp_path / "trusted_fingerprints.json",
    )

    save_trusted_fingerprint("alice", "bob", "AAAA")

    assert verify_trusted_fingerprint(
        "alice", "bob", "AAAA"
    ) == "trusted"


def test_wrong_passphrase_is_rejected(tmp_path):
    key_file = tmp_path / "private_keys.enc"
    identity = generate_identity()

    save_private_keys(
        identity,
        "correct-passphrase",
        str(key_file),
    )

    with pytest.raises(
        ValueError,
        match="Incorrect passphrase or damaged private-key file",
    ):
        load_private_keys(
            str(key_file),
            "wrong-passphrase",
        )
