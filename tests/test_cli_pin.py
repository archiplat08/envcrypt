"""Tests for envcrypt.cli_pin."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_pin import pin
from envcrypt.env_pin import PinError, save_pins


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"data")
    return p


def test_set_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(pin, ["set", str(vault_file), "DB_URL", "postgres://test"])
    assert result.exit_code == 0
    assert "Pinned DB_URL" in result.output


def test_set_cmd_shows_total_count(runner: CliRunner, vault_file: Path) -> None:
    runner.invoke(pin, ["set", str(vault_file), "KEY1", "v1"])
    result = runner.invoke(pin, ["set", str(vault_file), "KEY2", "v2"])
    assert "2 total pins" in result.output


def test_set_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_pin.pin_key", side_effect=PinError("boom")):
        result = runner.invoke(pin, ["set", str(vault_file), "K", "v"])
    assert result.exit_code == 1
    assert "Error: boom" in result.output


def test_unset_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    save_pins(vault_file, {"SECRET": "val"})
    result = runner.invoke(pin, ["unset", str(vault_file), "SECRET"])
    assert result.exit_code == 0
    assert "Unpinned 'SECRET'" in result.output


def test_unset_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(pin, ["unset", str(vault_file), "MISSING"])
    assert result.exit_code == 1
    assert "Error" in result.output


def test_list_cmd_empty(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(pin, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "No pinned keys" in result.output


def test_list_cmd_shows_pins(runner: CliRunner, vault_file: Path) -> None:
    save_pins(vault_file, {"API_KEY": "fixed", "DB_URL": "pg://"})
    result = runner.invoke(pin, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "API_KEY" in result.output
    assert "DB_URL" in result.output
