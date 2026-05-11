"""Tests for envcrypt.cli_quota CLI commands."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_quota import quota
from envcrypt.env_quota import QuotaError


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    f = tmp_path / "secrets.env.age"
    f.write_bytes(b"data")
    return f


def test_set_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(quota, ["set", str(vault_file), "20"])
    assert result.exit_code == 0
    assert "20" in result.output


def test_set_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_quota.save_quota", side_effect=QuotaError("bad")):
        result = runner.invoke(quota, ["set", str(vault_file), "0"])
    assert result.exit_code != 0
    assert "Error" in result.output


def test_show_cmd_no_quota(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(quota, ["show", str(vault_file)])
    assert result.exit_code == 0
    assert "No quota" in result.output


def test_show_cmd_with_quota(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(quota, ["set", str(vault_file), "15"])
    assert result.exit_code == 0
    result = runner.invoke(quota, ["show", str(vault_file)])
    assert result.exit_code == 0
    assert "15" in result.output


def test_show_cmd_corrupt_file_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_quota.load_quota", side_effect=QuotaError("corrupt")):
        result = runner.invoke(quota, ["show", str(vault_file)])
    assert result.exit_code != 0
    assert "Error" in result.output


def test_remove_cmd_when_quota_exists(runner: CliRunner, vault_file: Path) -> None:
    runner.invoke(quota, ["set", str(vault_file), "10"])
    result = runner.invoke(quota, ["remove", str(vault_file)])
    assert result.exit_code == 0
    assert "removed" in result.output


def test_remove_cmd_when_no_quota(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(quota, ["remove", str(vault_file)])
    assert result.exit_code == 0
    assert "No quota" in result.output
