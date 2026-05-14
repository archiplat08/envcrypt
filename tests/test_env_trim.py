"""Tests for envcrypt.env_trim."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_trim import TrimError, trim_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    return tmp_path / "secrets.env.age"


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-1FAKE")
    return p


def _patch_crypto(env: dict[str, str], vault_path: Path) -> tuple:
    vault_path.write_bytes(b"encrypted")
    decrypt_patch = patch(
        "envcrypt.env_trim.decrypt_env_file", return_value=env
    )
    encrypt_patch = patch("envcrypt.env_trim.encrypt_env_file")
    return decrypt_patch, encrypt_patch


def test_trim_vault_removes_unlisted_keys(tmp_path: Path, vault_file: Path, identity_file: Path) -> None:
    env = {"DB_HOST": "localhost", "DB_PORT": "5432", "OLD_KEY": "legacy"}
    schema = tmp_path / "schema.env"
    schema.write_text("DB_HOST=\nDB_PORT=\n")

    dp, ep = _patch_crypto(env, vault_file)
    with dp, ep as mock_enc:
        result = trim_vault(vault_file, schema, identity_file, ["age1abc"])

    assert "OLD_KEY" in result.removed
    assert "DB_HOST" in result.kept
    assert "DB_PORT" in result.kept
    assert result.count == 1
    mock_enc.assert_called_once()


def test_trim_vault_nothing_to_remove(tmp_path: Path, vault_file: Path, identity_file: Path) -> None:
    env = {"DB_HOST": "localhost"}
    schema = tmp_path / "schema.env"
    schema.write_text("DB_HOST=\n")

    dp, ep = _patch_crypto(env, vault_file)
    with dp, ep as mock_enc:
        result = trim_vault(vault_file, schema, identity_file, ["age1abc"])

    assert result.removed == []
    assert result.kept == ["DB_HOST"]
    mock_enc.assert_not_called()


def test_trim_vault_dry_run_does_not_write(tmp_path: Path, vault_file: Path, identity_file: Path) -> None:
    env = {"KEEP": "yes", "DROP": "no"}
    schema = tmp_path / "schema.env"
    schema.write_text("KEEP=\n")

    dp, ep = _patch_crypto(env, vault_file)
    with dp, ep as mock_enc:
        result = trim_vault(vault_file, schema, identity_file, ["age1abc"], dry_run=True)

    assert "DROP" in result.removed
    mock_enc.assert_not_called()


def test_trim_vault_missing_vault_raises(tmp_path: Path, identity_file: Path) -> None:
    schema = tmp_path / "schema.env"
    schema.write_text("KEY=\n")
    with pytest.raises(TrimError, match="Vault not found"):
        trim_vault(tmp_path / "missing.age", schema, identity_file, ["age1abc"])


def test_trim_vault_missing_schema_raises(tmp_path: Path, vault_file: Path, identity_file: Path) -> None:
    vault_file.write_bytes(b"data")
    with pytest.raises(TrimError, match="Schema file not found"):
        trim_vault(vault_file, tmp_path / "no_schema.env", identity_file, ["age1abc"])


def test_trim_vault_no_recipients_raises(tmp_path: Path, vault_file: Path, identity_file: Path) -> None:
    vault_file.write_bytes(b"data")
    schema = tmp_path / "schema.env"
    schema.write_text("KEY=\n")
    with pytest.raises(TrimError, match="recipient"):
        trim_vault(vault_file, schema, identity_file, [])


def test_trim_vault_custom_output(tmp_path: Path, vault_file: Path, identity_file: Path) -> None:
    env = {"A": "1", "B": "2"}
    schema = tmp_path / "schema.env"
    schema.write_text("A=\n")
    out = tmp_path / "trimmed.age"

    dp, ep = _patch_crypto(env, vault_file)
    with dp, ep as mock_enc:
        trim_vault(vault_file, schema, identity_file, ["age1abc"], output_path=out)

    args, _ = mock_enc.call_args
    assert args[1] == out
