"""Tests for envcrypt.cli_annotate."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_annotate import annotate
from envcrypt.env_annotate import AnnotateError


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"dummy")
    return p


def test_set_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(annotate, ["set", str(vault_file), "DB_HOST", "Primary DB"])
    assert result.exit_code == 0
    assert "DB_HOST" in result.output
    assert "Total annotations: 1" in result.output


def test_set_cmd_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch("envcrypt.cli_annotate.set_annotation", side_effect=AnnotateError("boom")):
        result = runner.invoke(annotate, ["set", str(vault_file), "K", "v"])
    assert result.exit_code == 1
    assert "boom" in result.output


def test_get_cmd_prints_annotation(runner: CliRunner, vault_file: Path) -> None:
    runner.invoke(annotate, ["set", str(vault_file), "MY_KEY", "some note"])
    result = runner.invoke(annotate, ["get", str(vault_file), "MY_KEY"])
    assert result.exit_code == 0
    assert "some note" in result.output


def test_get_cmd_missing_key(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(annotate, ["get", str(vault_file), "GHOST"])
    assert result.exit_code == 0
    assert "No annotation found" in result.output


def test_remove_cmd_success(runner: CliRunner, vault_file: Path) -> None:
    runner.invoke(annotate, ["set", str(vault_file), "X", "val"])
    result = runner.invoke(annotate, ["remove", str(vault_file), "X"])
    assert result.exit_code == 0
    assert "removed" in result.output


def test_list_cmd_empty(runner: CliRunner, vault_file: Path) -> None:
    result = runner.invoke(annotate, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "No annotations found" in result.output


def test_list_cmd_shows_entries(runner: CliRunner, vault_file: Path) -> None:
    runner.invoke(annotate, ["set", str(vault_file), "A", "alpha"])
    runner.invoke(annotate, ["set", str(vault_file), "B", "beta"])
    result = runner.invoke(annotate, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "A: alpha" in result.output
    assert "B: beta" in result.output
