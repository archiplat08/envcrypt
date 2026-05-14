"""Tests for envcrypt.env_preview."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_preview import PreviewEntry, PreviewError, PreviewResult, preview_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    f = tmp_path / "secrets.env.age"
    f.write_text("placeholder")
    return f


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    f = tmp_path / "key.txt"
    f.write_text("AGE-SECRET-KEY-1...")
    return f


def _patch_decrypt(plaintext: str):
    return patch("envcrypt.env_preview.decrypt", return_value=plaintext)


def test_preview_vault_returns_all_keys(vault_file, identity_file):
    content = "DB_HOST=localhost\nDB_PASSWORD=s3cr3t\nAPP_ENV=production\n"
    with _patch_decrypt(content):
        result = preview_vault(vault_file, identity_file)

    assert result.total == 3
    assert result.vault == str(vault_file)


def test_preview_vault_masks_sensitive_keys(vault_file, identity_file):
    content = "DB_PASSWORD=s3cr3t\nAPP_ENV=production\n"
    with _patch_decrypt(content):
        result = preview_vault(vault_file, identity_file, mask_sensitive=True)

    masked = {e.key: e for e in result.entries}
    assert masked["DB_PASSWORD"].masked is True
    assert masked["DB_PASSWORD"].value == "s3cr3t"  # raw value still accessible
    assert masked["APP_ENV"].masked is False


def test_preview_vault_no_masking(vault_file, identity_file):
    content = "API_TOKEN=abc123\n"
    with _patch_decrypt(content):
        result = preview_vault(vault_file, identity_file, mask_sensitive=False)

    assert result.entries[0].masked is False
    assert result.masked_count == 0


def test_preview_vault_filter_specific_keys(vault_file, identity_file):
    content = "FOO=1\nBAR=2\nBAZ=3\n"
    with _patch_decrypt(content):
        result = preview_vault(vault_file, identity_file, keys=["FOO", "BAZ"])

    assert result.total == 2
    assert {e.key for e in result.entries} == {"FOO", "BAZ"}


def test_preview_vault_missing_vault_raises(tmp_path, identity_file):
    with pytest.raises(PreviewError, match="Vault file not found"):
        preview_vault(tmp_path / "missing.age", identity_file)


def test_preview_vault_missing_identity_raises(vault_file, tmp_path):
    with pytest.raises(PreviewError, match="Identity file not found"):
        preview_vault(vault_file, tmp_path / "missing_key.txt")


def test_preview_vault_decrypt_failure_raises(vault_file, identity_file):
    with patch("envcrypt.env_preview.decrypt", side_effect=RuntimeError("bad key")):
        with pytest.raises(PreviewError, match="Decryption failed"):
            preview_vault(vault_file, identity_file)


def test_preview_result_as_dict_masks_sensitive(vault_file, identity_file):
    content = "SECRET_KEY=topsecret\nHOST=localhost\n"
    with _patch_decrypt(content):
        result = preview_vault(vault_file, identity_file, mask_sensitive=True)

    d = result.as_dict()
    assert d["SECRET_KEY"] == "****"
    assert d["HOST"] == "localhost"


def test_preview_entry_str_masked():
    entry = PreviewEntry(key="TOKEN", value="abc", masked=True)
    assert str(entry) == "TOKEN=****"


def test_preview_entry_str_unmasked():
    entry = PreviewEntry(key="HOST", value="localhost", masked=False)
    assert str(entry) == "HOST=localhost"


def test_preview_result_summary(vault_file, identity_file):
    content = "API_KEY=secret\nAPP_NAME=myapp\n"
    with _patch_decrypt(content):
        result = preview_vault(vault_file, identity_file)

    summary = result.summary()
    assert "2 key(s)" in summary
    assert str(vault_file) in summary
