"""Tests for envcrypt.env_rename."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_rename import RenameError, rename_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    return tmp_path / "test.env.age"


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-FAKE")
    return p


def _patch_crypto(monkeypatch, env_text: str, recipients=None):
    """Patch decrypt/encrypt/load_recipients for rename tests."""
    if recipients is None:
        recipients = ["age1fakerecipient"]
    monkeypatch.setattr("envcrypt.env_rename.decrypt", lambda *_a, **_kw: env_text)
    monkeypatch.setattr("envcrypt.env_rename.encrypt", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        "envcrypt.env_rename.load_recipients", lambda *_a, **_kw: recipients
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_rename_key_success(tmp_path, vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"encrypted")
    _patch_crypto(monkeypatch, "FOO=bar\nBAZ=qux\n")

    result = rename_key(vault_file, identity_file, "FOO", "FOO_RENAMED")

    assert result.old_key == "FOO"
    assert result.new_key == "FOO_RENAMED"
    assert result.aliased is False


def test_rename_key_keep_alias(tmp_path, vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"encrypted")
    captured: list[str] = []

    def fake_encrypt(data, *_a, **_kw):
        captured.append(data.decode())

    monkeypatch.setattr("envcrypt.env_rename.decrypt", lambda *_a, **_kw: "FOO=bar\n")
    monkeypatch.setattr("envcrypt.env_rename.encrypt", fake_encrypt)
    monkeypatch.setattr(
        "envcrypt.env_rename.load_recipients", lambda *_a, **_kw: ["age1x"]
    )

    result = rename_key(vault_file, identity_file, "FOO", "FOO_NEW", keep_alias=True)

    assert result.aliased is True
    assert "FOO=bar" in captured[0]
    assert "FOO_NEW=bar" in captured[0]


def test_rename_missing_vault_raises(tmp_path, identity_file):
    with pytest.raises(RenameError, match="Vault not found"):
        rename_key(tmp_path / "nope.age", identity_file, "A", "B")


def test_rename_no_recipients_raises(vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"x")
    monkeypatch.setattr(
        "envcrypt.env_rename.load_recipients", lambda *_a, **_kw: []
    )
    with pytest.raises(RenameError, match="No recipients"):
        rename_key(vault_file, identity_file, "A", "B")


def test_rename_missing_key_raises(vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"x")
    _patch_crypto(monkeypatch, "FOO=bar\n")
    with pytest.raises(RenameError, match="Key 'MISSING' not found"):
        rename_key(vault_file, identity_file, "MISSING", "NEW")


def test_rename_existing_target_raises(vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"x")
    _patch_crypto(monkeypatch, "FOO=bar\nNEW=taken\n")
    with pytest.raises(RenameError, match="already exists"):
        rename_key(vault_file, identity_file, "FOO", "NEW")
