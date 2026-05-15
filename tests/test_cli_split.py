"""Tests for envcrypt.cli_split."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_split import split
from envcrypt.env_split import SplitError, SplitResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


def _make_result(tmp_path: Path) -> SplitResult:
    return SplitResult(
        outputs={"APP": tmp_path / "app.env.age", "DB": tmp_path / "db.env.age"},
        key_counts={"APP": 2, "DB": 1},
        leftover_count=0,
    )


def test_run_cmd_success(runner, vault_file, tmp_path):
    result_obj = _make_result(tmp_path)
    with patch("envcrypt.cli_split.split_vault", return_value=result_obj) as mock_split:
        result = runner.invoke(
            split,
            ["run", str(vault_file), "APP", "DB", "--identity", str(tmp_path / "id.txt")],
        )
    assert result.exit_code == 0
    assert "APP" in result.output
    assert "DB" in result.output
    assert "Done." in result.output
    mock_split.assert_called_once()


def test_run_cmd_no_matches(runner, vault_file, tmp_path):
    empty = SplitResult()
    with patch("envcrypt.cli_split.split_vault", return_value=empty):
        result = runner.invoke(
            split,
            ["run", str(vault_file), "XYZ", "--identity", str(tmp_path / "id.txt")],
        )
    assert result.exit_code == 0
    assert "No keys matched" in result.output


def test_run_cmd_error_exits_nonzero(runner, vault_file, tmp_path):
    with patch("envcrypt.cli_split.split_vault", side_effect=SplitError("boom")):
        result = runner.invoke(
            split,
            ["run", str(vault_file), "APP", "--identity", str(tmp_path / "id.txt")],
        )
    assert result.exit_code == 1
    assert "Error: boom" in result.output
