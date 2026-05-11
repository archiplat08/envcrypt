"""Tests for envcrypt.cli_access."""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from envcrypt.cli_access import access
from envcrypt.env_access import record_access, _access_log_path


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    v = tmp_path / "secrets.env.age"
    v.write_bytes(b"dummy")
    return v


def test_log_empty(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(access, ["log", str(vault_file)])
    assert result.exit_code == 0
    assert "No access log entries" in result.output


def test_log_shows_entries(runner: CliRunner, vault_file: Path) -> None:
    record_access(vault_file, "read", "DB_PASS", actor="alice")
    result = runner.invoke(access, ["log", str(vault_file)])
    assert result.exit_code == 0
    assert "DB_PASS" in result.output
    assert "alice" in result.output


def test_log_filter_by_action(runner: CliRunner, vault_file: Path) -> None:
    record_access(vault_file, "read", "A")
    record_access(vault_file, "write", "B")
    result = runner.invoke(access, ["log", str(vault_file), "--action", "write"])
    assert result.exit_code == 0
    assert "B" in result.output
    assert "A" not in result.output


def test_log_filter_by_key(runner: CliRunner, vault_file: Path) -> None:
    record_access(vault_file, "read", "ALPHA")
    record_access(vault_file, "read", "BETA")
    result = runner.invoke(access, ["log", str(vault_file), "--key", "ALPHA"])
    assert result.exit_code == 0
    assert "ALPHA" in result.output
    assert "BETA" not in result.output


def test_clear_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    record_access(vault_file, "read", "X")
    result = runner.invoke(access, ["clear", str(vault_file), "--yes"])
    assert result.exit_code == 0
    assert "Cleared 1" in result.output
    assert not _access_log_path(vault_file).exists()


def test_clear_cmd_no_file(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(access, ["clear", str(vault_file), "--yes"])
    assert result.exit_code == 0
    assert "Cleared 0" in result.output


def test_log_corrupt_log_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    _access_log_path(vault_file).write_text("!!bad")
    result = runner.invoke(access, ["log", str(vault_file)])
    assert result.exit_code == 1
    assert "Error" in result.output
