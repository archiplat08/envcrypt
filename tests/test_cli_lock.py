"""Tests for envcrypt.cli_lock."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_lock import lock
from envcrypt.env_lock import LockError, LockInfo


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_text("enc")
    return p


def test_lock_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    info = LockInfo(vault=str(vault_file), locked_by="alice", locked_at="2024-01-01T00:00:00Z")
    with patch("envcrypt.cli_lock.lock_vault", return_value=info) as mock:
        result = runner.invoke(lock, ["lock", str(vault_file), "--actor", "alice"])
    mock.assert_called_once_with(vault_file, actor="alice")
    assert result.exit_code == 0
    assert "Locked" in result.output
    assert "alice" in result.output


def test_lock_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_lock.lock_vault", side_effect=LockError("already locked")):
        result = runner.invoke(lock, ["lock", str(vault_file)])
    assert result.exit_code == 1
    assert "already locked" in result.output


def test_unlock_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_lock.unlock_vault") as mock:
        result = runner.invoke(lock, ["unlock", str(vault_file)])
    mock.assert_called_once_with(vault_file)
    assert result.exit_code == 0
    assert "Unlocked" in result.output


def test_unlock_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_lock.unlock_vault", side_effect=LockError("not locked")):
        result = runner.invoke(lock, ["unlock", str(vault_file)])
    assert result.exit_code == 1


def test_status_cmd_unlocked(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_lock.is_locked", return_value=False):
        result = runner.invoke(lock, ["status", str(vault_file)])
    assert result.exit_code == 0
    assert "unlocked" in result.output


def test_status_cmd_locked(runner: CliRunner, vault_file: Path) -> None:
    info = LockInfo(vault=str(vault_file), locked_by="bob", locked_at="2024-06-01T12:00:00Z")
    with patch("envcrypt.cli_lock.is_locked", return_value=True), \
         patch("envcrypt.cli_lock.read_lock_info", return_value=info):
        result = runner.invoke(lock, ["status", str(vault_file)])
    assert result.exit_code == 0
    assert "locked" in result.output
    assert "bob" in result.output


def test_status_cmd_corrupt_lock_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_lock.is_locked", return_value=True), \
         patch("envcrypt.cli_lock.read_lock_info", side_effect=LockError("Corrupt")):
        result = runner.invoke(lock, ["status", str(vault_file)])
    assert result.exit_code == 1
