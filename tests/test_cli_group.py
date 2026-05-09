"""Tests for envcrypt.cli_group."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from envcrypt.cli_group import group
from envcrypt.env_group import add_key_to_group, load_groups


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"")
    return p


def test_add_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(group, ["add", str(vault_file), "backend", "DB_URL"])
    assert result.exit_code == 0
    assert "Added 'DB_URL' to group 'backend'" in result.output
    assert "DB_URL" in load_groups(vault_file)["backend"]


def test_remove_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    result = runner.invoke(group, ["remove", str(vault_file), "backend", "DB_URL"])
    assert result.exit_code == 0
    assert "Removed" in result.output


def test_remove_cmd_missing_group_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(group, ["remove", str(vault_file), "ghost", "KEY"])
    assert result.exit_code != 0
    assert "Error" in result.output


def test_delete_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    result = runner.invoke(group, ["delete", str(vault_file), "backend"])
    assert result.exit_code == 0
    assert "Deleted group 'backend'" in result.output


def test_delete_cmd_missing_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(group, ["delete", str(vault_file), "ghost"])
    assert result.exit_code != 0


def test_list_cmd_all_groups(runner: CliRunner, vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    add_key_to_group(vault_file, "frontend", "API_KEY")
    result = runner.invoke(group, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "backend" in result.output
    assert "frontend" in result.output


def test_list_cmd_no_groups(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(group, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "No groups defined" in result.output


def test_list_cmd_specific_group(runner: CliRunner, vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    add_key_to_group(vault_file, "backend", "DB_PASS")
    result = runner.invoke(group, ["list", str(vault_file), "--group", "backend"])
    assert result.exit_code == 0
    assert "DB_URL" in result.output
    assert "DB_PASS" in result.output


def test_which_cmd_shows_groups(runner: CliRunner, vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    add_key_to_group(vault_file, "infra", "DB_URL")
    result = runner.invoke(group, ["which", str(vault_file), "DB_URL"])
    assert result.exit_code == 0
    assert "backend" in result.output
    assert "infra" in result.output


def test_which_cmd_no_groups(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(group, ["which", str(vault_file), "ORPHAN"])
    assert result.exit_code == 0
    assert "not in any group" in result.output
