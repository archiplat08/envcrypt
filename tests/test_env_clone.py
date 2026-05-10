"""Tests for envcrypt.env_clone."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from envcrypt.env_clone import CloneError, clone_vault


PLAINTEXT = "DB_HOST=localhost\nDB_PASS=secret\nAPI_KEY=abc123\n"
RECIPIENTS = ["age1abc", "age1def"]


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(plaintext: str = PLAINTEXT, recipients: list[str] | None = None):
    recs = recipients if recipients is not None else RECIPIENTS
    return (
        patch("envcrypt.env_clone.decrypt", return_value=plaintext),
        patch("envcrypt.env_clone.encrypt"),
        patch("envcrypt.env_clone.load_recipients", return_value=recs),
    )


def test_clone_vault_success(vault_file: Path, identity_file: Path, tmp_path: Path):
    dest = tmp_path / "clone.env.age"
    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        p_dec = patch("envcrypt.env_clone.decrypt", return_value=PLAINTEXT)
        p_enc = patch("envcrypt.env_clone.encrypt")
        p_rec = patch("envcrypt.env_clone.load_recipients", return_value=RECIPIENTS)
        with p_dec, p_enc as mock_enc, p_rec:
            result = clone_vault(vault_file, dest, identity_file)
    assert set(result.keys_copied) == {"DB_HOST", "DB_PASS", "API_KEY"}
    assert result.keys_skipped == []
    assert result.destination == dest


def test_clone_vault_include_filter(vault_file: Path, identity_file: Path, tmp_path: Path):
    dest = tmp_path / "clone.env.age"
    p_dec = patch("envcrypt.env_clone.decrypt", return_value=PLAINTEXT)
    p_enc = patch("envcrypt.env_clone.encrypt")
    p_rec = patch("envcrypt.env_clone.load_recipients", return_value=RECIPIENTS)
    with p_dec, p_enc, p_rec:
        result = clone_vault(vault_file, dest, identity_file, include=["DB_HOST"])
    assert result.keys_copied == ["DB_HOST"]
    assert set(result.keys_skipped) == {"DB_PASS", "API_KEY"}


def test_clone_vault_exclude_filter(vault_file: Path, identity_file: Path, tmp_path: Path):
    dest = tmp_path / "clone.env.age"
    p_dec = patch("envcrypt.env_clone.decrypt", return_value=PLAINTEXT)
    p_enc = patch("envcrypt.env_clone.encrypt")
    p_rec = patch("envcrypt.env_clone.load_recipients", return_value=RECIPIENTS)
    with p_dec, p_enc, p_rec:
        result = clone_vault(vault_file, dest, identity_file, exclude=["API_KEY"])
    assert "API_KEY" not in result.keys_copied
    assert "API_KEY" in result.keys_skipped


def test_clone_vault_include_and_exclude_raises(vault_file: Path, identity_file: Path, tmp_path: Path):
    dest = tmp_path / "clone.env.age"
    with pytest.raises(CloneError, match="not both"):
        clone_vault(vault_file, dest, identity_file, include=["A"], exclude=["B"])


def test_clone_vault_missing_source_raises(tmp_path: Path, identity_file: Path):
    with pytest.raises(CloneError, match="not found"):
        clone_vault(tmp_path / "missing.age", tmp_path / "out.age", identity_file)


def test_clone_vault_no_recipients_raises(vault_file: Path, identity_file: Path, tmp_path: Path):
    dest = tmp_path / "clone.env.age"
    p_dec = patch("envcrypt.env_clone.decrypt", return_value=PLAINTEXT)
    p_rec = patch("envcrypt.env_clone.load_recipients", return_value=[])
    with p_dec, p_rec, pytest.raises(CloneError, match="No recipients"):
        clone_vault(vault_file, dest, identity_file)


def test_clone_result_summary(vault_file: Path, identity_file: Path, tmp_path: Path):
    dest = tmp_path / "clone.env.age"
    p_dec = patch("envcrypt.env_clone.decrypt", return_value=PLAINTEXT)
    p_enc = patch("envcrypt.env_clone.encrypt")
    p_rec = patch("envcrypt.env_clone.load_recipients", return_value=RECIPIENTS)
    with p_dec, p_enc, p_rec:
        result = clone_vault(vault_file, dest, identity_file)
    summary = result.summary()
    assert "Cloned" in summary
    assert str(dest) in summary
