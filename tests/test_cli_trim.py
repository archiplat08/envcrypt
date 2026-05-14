"""Tests for envcrypt.cli_trim."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_trim import trim
from envcrypt.env_trim import TrimError, TrimResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


def _make_result(removed: list[str], kept: list[str]) -> TrimResult:
    r = TrimResult()
    r.removed = removed
    r.kept = kept
    return r


def test_run_cmd_no_changes(runner: CliRunner, tmp_path: Path, vault_file: Path) -> None:
    schema = tmp_path / "schema.env"
    schema.write_text("KEY=\n")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET")
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1abc\n")

    result = _make_result([], ["KEY"])
    with patch("envcrypt.cli_trim.trim_vault", return_value=result), \
         patch("envcrypt.cli_trim.load_recipients", return_value=["age1abc"]):
        out = runner.invoke(
            trim,
            ["run", str(vault_file), str(schema), "-i", str(identity)],
        )

    assert out.exit_code == 0
    assert "clean" in out.output


def test_run_cmd_with_removed_keys(runner: CliRunner, tmp_path: Path, vault_file: Path) -> None:
    schema = tmp_path / "schema.env"
    schema.write_text("KEEP=\n")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET")

    result = _make_result(["OLD_KEY"], ["KEEP"])
    with patch("envcrypt.cli_trim.trim_vault", return_value=result), \
         patch("envcrypt.cli_trim.load_recipients", return_value=["age1abc"]):
        out = runner.invoke(
            trim,
            ["run", str(vault_file), str(schema), "-i", str(identity)],
        )

    assert out.exit_code == 0
    assert "OLD_KEY" in out.output
    assert "Removed 1" in out.output


def test_run_cmd_dry_run_prefix(runner: CliRunner, tmp_path: Path, vault_file: Path) -> None:
    schema = tmp_path / "schema.env"
    schema.write_text("KEEP=\n")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET")

    result = _make_result(["STALE"], ["KEEP"])
    with patch("envcrypt.cli_trim.trim_vault", return_value=result), \
         patch("envcrypt.cli_trim.load_recipients", return_value=["age1abc"]):
        out = runner.invoke(
            trim,
            ["run", str(vault_file), str(schema), "-i", str(identity), "--dry-run"],
        )

    assert out.exit_code == 0
    assert "[dry-run]" in out.output


def test_run_cmd_error_exits_nonzero(runner: CliRunner, tmp_path: Path, vault_file: Path) -> None:
    schema = tmp_path / "schema.env"
    schema.write_text("KEY=\n")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET")

    with patch("envcrypt.cli_trim.trim_vault", side_effect=TrimError("boom")), \
         patch("envcrypt.cli_trim.load_recipients", return_value=["age1abc"]):
        out = runner.invoke(
            trim,
            ["run", str(vault_file), str(schema), "-i", str(identity)],
        )

    assert out.exit_code != 0
    assert "boom" in out.output
