"""Tests for envcrypt.rotate and envcrypt.cli_rotate."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envcrypt.rotate import RotationError, rotate_vault
from envcrypt.cli_rotate import rotate

DECRYPTED_ENV = "KEY1=value1\nKEY2=value2\n"
RECIPIENTS = ["age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"]


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    f = tmp_path / ".env.age"
    f.write_bytes(b"encrypted-blob")
    return f


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    f = tmp_path / "key.txt"
    f.write_text("AGE-SECRET-KEY-1...")
    return f


@patch("envcrypt.rotate.record")
@patch("envcrypt.rotate.encrypt")
@patch("envcrypt.rotate.load_recipients", return_value=RECIPIENTS)
@patch("envcrypt.rotate.decrypt", return_value=DECRYPTED_ENV)
def test_rotate_vault_success(mock_dec, mock_load, mock_enc, mock_record, vault_file, identity_file):
    out = rotate_vault(vault_file, identity_file)
    mock_dec.assert_called_once()
    mock_enc.assert_called_once()
    mock_record.assert_called_once()
    assert out == vault_file


@patch("envcrypt.rotate.load_recipients", return_value=[])
def test_rotate_vault_no_recipients_raises(mock_load, vault_file, identity_file):
    with pytest.raises(RotationError, match="No recipients"):
        rotate_vault(vault_file, identity_file)


@patch("envcrypt.rotate.load_recipients", return_value=RECIPIENTS)
@patch("envcrypt.rotate.decrypt", side_effect=RuntimeError("bad key"))
def test_rotate_vault_decrypt_failure_raises(mock_dec, mock_load, vault_file, identity_file):
    with pytest.raises(RotationError, match="Failed to decrypt"):
        rotate_vault(vault_file, identity_file)


@patch("envcrypt.rotate.record")
@patch("envcrypt.rotate.encrypt", side_effect=RuntimeError("age error"))
@patch("envcrypt.rotate.load_recipients", return_value=RECIPIENTS)
@patch("envcrypt.rotate.decrypt", return_value=DECRYPTED_ENV)
def test_rotate_vault_encrypt_failure_raises(mock_dec, mock_load, mock_enc, mock_record, vault_file, identity_file):
    with pytest.raises(RotationError, match="Failed to re-encrypt"):
        rotate_vault(vault_file, identity_file)


# --- CLI tests ---

@pytest.fixture()
def runner():
    return CliRunner()


@patch("envcrypt.cli_rotate.rotate_vault")
def test_cli_rotate_run_success(mock_rotate, runner, vault_file, identity_file):
    mock_rotate.return_value = vault_file
    result = runner.invoke(
        rotate,
        ["run", str(vault_file), "--identity", str(identity_file)],
    )
    assert result.exit_code == 0
    assert "Rotated vault written to" in result.output


@patch("envcrypt.cli_rotate.rotate_vault", side_effect=RotationError("no recipients"))
def test_cli_rotate_run_error(mock_rotate, runner, vault_file, identity_file):
    result = runner.invoke(
        rotate,
        ["run", str(vault_file), "--identity", str(identity_file)],
    )
    assert result.exit_code != 0
    assert "no recipients" in result.output
