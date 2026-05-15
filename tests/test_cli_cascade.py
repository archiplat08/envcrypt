"""Tests for envcrypt.cli_cascade."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_cascade import cascade
from envcrypt.env_cascade import CascadeError, CascadeResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "vault.env.age"
    p.write_bytes(b"placeholder")
    return p


def _make_result(**kwargs) -> CascadeResult:
    defaults = dict(
        merged={"KEY": "val"},
        sources={"KEY": "vault.env.age"},
        overridden={},
    )
    defaults.update(kwargs)
    return CascadeResult(**defaults)


def test_run_cmd_success(runner, tmp_path, vault_file):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1...")
    output = tmp_path / "merged.env.age"
    result_obj = _make_result()

    with patch("envcrypt.cli_cascade.cascade_vaults", return_value=result_obj):
        result = runner.invoke(
            cascade,
            ["run", str(vault_file), "-i", str(identity), "-o", str(output)],
        )

    assert result.exit_code == 0
    assert "1 keys merged" in result.output


def test_run_cmd_verbose_shows_sources(runner, tmp_path, vault_file):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1...")
    output = tmp_path / "merged.env.age"
    result_obj = _make_result()

    with patch("envcrypt.cli_cascade.cascade_vaults", return_value=result_obj):
        result = runner.invoke(
            cascade,
            ["run", str(vault_file), "-i", str(identity), "-o", str(output), "--verbose"],
        )

    assert result.exit_code == 0
    assert "Key sources" in result.output
    assert "KEY" in result.output


def test_run_cmd_shows_override_count(runner, tmp_path, vault_file):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1...")
    output = tmp_path / "merged.env.age"
    result_obj = _make_result(
        merged={"KEY": "b"},
        sources={"KEY": "b.env.age"},
        overridden={"KEY": ["a.env.age", "b.env.age"]},
    )

    with patch("envcrypt.cli_cascade.cascade_vaults", return_value=result_obj):
        result = runner.invoke(
            cascade,
            ["run", str(vault_file), "-i", str(identity), "-o", str(output)],
        )

    assert result.exit_code == 0
    assert "1 key(s) were overridden" in result.output


def test_run_cmd_error_exits_nonzero(runner, tmp_path, vault_file):
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1...")
    output = tmp_path / "merged.env.age"

    with patch("envcrypt.cli_cascade.cascade_vaults", side_effect=CascadeError("boom")):
        result = runner.invoke(
            cascade,
            ["run", str(vault_file), "-i", str(identity), "-o", str(output)],
        )

    assert result.exit_code != 0
    assert "boom" in result.output
