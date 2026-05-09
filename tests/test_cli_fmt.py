"""Tests for envcrypt.cli_fmt."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_fmt import fmt
from envcrypt.env_fmt import FmtError, FmtResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


def _make_result(changed: bool = True) -> FmtResult:
    return FmtResult(
        original="B=2\nA=1\n",
        formatted="A=1\nB=2\n",
        changed=changed,
        sorted_keys=True,
        normalized_quotes=True,
    )


def test_run_cmd_success(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with patch("envcrypt.cli_fmt.format_vault", return_value=_make_result()) as mock_fmt:
        result = runner.invoke(
            fmt,
            ["run", str(vault_file), "-i", str(identity), "-r", str(recipients)],
        )

    assert result.exit_code == 0
    assert "Formatted" in result.output
    mock_fmt.assert_called_once()


def test_run_cmd_no_changes(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with patch("envcrypt.cli_fmt.format_vault", return_value=_make_result(changed=False)):
        result = runner.invoke(
            fmt,
            ["run", str(vault_file), "-i", str(identity), "-r", str(recipients)],
        )

    assert result.exit_code == 0
    assert "no changes" in result.output


def test_run_cmd_dry_run_shows_diff(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with patch("envcrypt.cli_fmt.format_vault", return_value=_make_result(changed=True)):
        result = runner.invoke(
            fmt,
            ["run", str(vault_file), "-i", str(identity), "-r", str(recipients), "--dry-run"],
        )

    assert result.exit_code == 0
    assert "dry-run" in result.output
    assert "NOT modified" in result.output


def test_run_cmd_dry_run_no_change(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with patch("envcrypt.cli_fmt.format_vault", return_value=_make_result(changed=False)):
        result = runner.invoke(
            fmt,
            ["run", str(vault_file), "-i", str(identity), "-r", str(recipients), "--dry-run"],
        )

    assert result.exit_code == 0
    assert "no changes needed" in result.output


def test_run_cmd_fmt_error_exits_nonzero(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with patch("envcrypt.cli_fmt.format_vault", side_effect=FmtError("boom")):
        result = runner.invoke(
            fmt,
            ["run", str(vault_file), "-i", str(identity), "-r", str(recipients)],
        )

    assert result.exit_code != 0
    assert "boom" in result.output
