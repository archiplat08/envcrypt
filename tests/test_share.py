"""Tests for envcrypt.share."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_share import share
from envcrypt.share import ShareError, share_subset, share_vault

SAMPLE_ENV = b"DB_HOST=localhost\nDB_PASS=secret\nAPI_KEY=abc123\n"
RECIPIENT = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / ".env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(decrypt_return: bytes = SAMPLE_ENV):
    """Return a context-manager tuple patching decrypt and encrypt."""
    mock_decrypt = patch("envcrypt.share.decrypt", return_value=decrypt_return)
    mock_encrypt = patch("envcrypt.share.encrypt")
    return mock_decrypt, mock_encrypt


def test_share_vault_success(vault_file: Path, identity_file: Path, tmp_path: Path):
    out = tmp_path / "shared.age"
    d, e = _patch_crypto()
    with d, e as mock_enc:
        result = share_vault(vault_file, identity_file, [RECIPIENT], output_path=out)
    assert result == out
    mock_enc.assert_called_once()


def test_share_vault_default_output_name(vault_file: Path, identity_file: Path):
    d, e = _patch_crypto()
    with d, e:
        result = share_vault(vault_file, identity_file, [RECIPIENT])
    assert result.name == ".env.shared.age"


def test_share_vault_no_recipients_raises(vault_file: Path, identity_file: Path):
    with pytest.raises(ShareError, match="empty"):
        share_vault(vault_file, identity_file, [])


def test_share_vault_loads_recipients_from_file(
    vault_file: Path, identity_file: Path, tmp_path: Path
):
    keys_file = tmp_path / "keys.txt"
    d, e = _patch_crypto()
    with patch("envcrypt.share.load_recipients", return_value=[RECIPIENT]) as mock_lr:
        with d, e:
            share_vault(vault_file, identity_file, [], keys_file=keys_file)
    mock_lr.assert_called_once_with(keys_file)


def test_share_vault_missing_file(identity_file: Path, tmp_path: Path):
    with pytest.raises(ShareError, match="not found"):
        share_vault(tmp_path / "missing.age", identity_file, [RECIPIENT])


def test_share_subset_success(vault_file: Path, identity_file: Path, tmp_path: Path):
    out = tmp_path / "subset.age"
    d, e = _patch_crypto()
    with d, e as mock_enc:
        result = share_subset(vault_file, identity_file, ["DB_HOST"], [RECIPIENT], out)
    assert result == out
    mock_enc.assert_called_once()


def test_share_subset_missing_key_raises(vault_file: Path, identity_file: Path):
    d, e = _patch_crypto()
    with d, e:
        with pytest.raises(ShareError, match="MISSING_KEY"):
            share_subset(vault_file, identity_file, ["MISSING_KEY"], [RECIPIENT])


def test_share_subset_empty_keys_raises(vault_file: Path, identity_file: Path):
    with pytest.raises(ShareError, match="empty"):
        share_subset(vault_file, identity_file, [], [RECIPIENT])


# --- CLI tests ---


@pytest.fixture()
def runner():
    return CliRunner()


def test_cli_share_vault(runner: CliRunner, vault_file: Path, identity_file: Path, tmp_path: Path):
    out = tmp_path / "shared.age"
    with patch("envcrypt.cli_share.share_vault", return_value=out) as mock_sv:
        result = runner.invoke(
            share,
            ["vault", str(vault_file), str(identity_file), "-r", RECIPIENT, "-o", str(out)],
        )
    assert result.exit_code == 0
    assert str(out) in result.output
    mock_sv.assert_called_once()


def test_cli_share_vault_error(runner: CliRunner, vault_file: Path, identity_file: Path):
    with patch("envcrypt.cli_share.share_vault", side_effect=ShareError("boom")):
        result = runner.invoke(
            share, ["vault", str(vault_file), str(identity_file), "-r", RECIPIENT]
        )
    assert result.exit_code != 0
    assert "boom" in result.output
