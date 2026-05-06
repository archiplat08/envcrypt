"""Tests for envcrypt.cli_sign."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_sign import sign
from envcrypt.env_sign import SignError, SignatureInfo


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"data")
    return p


def _make_info(vault: str = "secrets.env.age") -> SignatureInfo:
    return SignatureInfo(
        vault=vault, sha256="abc123", signer="alice", timestamp="2024-01-01T00:00:00"
    )


def test_sign_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_sign.sign_vault", return_value=_make_info()) as m:
        result = runner.invoke(sign, ["sign", str(vault_file), "--signer", "alice"])
    assert result.exit_code == 0
    assert "Signed" in result.output
    assert "abc123" in result.output
    m.assert_called_once_with(vault_file, signer="alice")


def test_sign_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_sign.sign_vault", side_effect=SignError("boom")):
        result = runner.invoke(sign, ["sign", str(vault_file)])
    assert result.exit_code == 1
    assert "boom" in result.output


def test_verify_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_sign.verify_vault", return_value=_make_info()) as m:
        result = runner.invoke(sign, ["verify", str(vault_file)])
    assert result.exit_code == 0
    assert "OK" in result.output
    assert "abc123" in result.output
    m.assert_called_once_with(vault_file)


def test_verify_cmd_failure_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch(
        "envcrypt.cli_sign.verify_vault",
        side_effect=SignError("Signature mismatch"),
    ):
        result = runner.invoke(sign, ["verify", str(vault_file)])
    assert result.exit_code == 1
    assert "FAILED" in result.output
    assert "Signature mismatch" in result.output
