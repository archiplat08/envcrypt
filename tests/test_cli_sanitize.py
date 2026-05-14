"""Tests for envcrypt.cli_sanitize."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_sanitize import run_cmd
from envcrypt.env_sanitize import SanitizeError, SanitizeResult


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path):
    p = tmp_path / "env.age"
    p.write_bytes(b"encrypted")
    return p


def _make_result(changed=None, skipped=None):
    return SanitizeResult(
        sanitized={},
        changed_keys=changed or [],
        skipped_keys=skipped or [],
    )


def test_run_cmd_no_changes(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("key")
    with patch(
        "envcrypt.cli_sanitize.sanitize_vault",
        return_value=_make_result(),
    ):
        result = runner.invoke(
            run_cmd, [str(vault_file), "--identity", str(identity)]
        )
    assert result.exit_code == 0
    assert "already clean" in result.output


def test_run_cmd_with_changes(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("key")
    with patch(
        "envcrypt.cli_sanitize.sanitize_vault",
        return_value=_make_result(changed=["BAD_KEY"]),
    ):
        result = runner.invoke(
            run_cmd, [str(vault_file), "--identity", str(identity)]
        )
    assert result.exit_code == 0
    assert "BAD_KEY" in result.output
    assert "1 key(s) sanitized" in result.output


def test_run_cmd_error_exits_nonzero(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("key")
    with patch(
        "envcrypt.cli_sanitize.sanitize_vault",
        side_effect=SanitizeError("boom"),
    ):
        result = runner.invoke(
            run_cmd, [str(vault_file), "--identity", str(identity)]
        )
    assert result.exit_code == 1
    assert "boom" in result.output


def test_run_cmd_skip_option_passed(runner, vault_file, tmp_path):
    identity = tmp_path / "key.txt"
    identity.write_text("key")
    with patch(
        "envcrypt.cli_sanitize.sanitize_vault",
        return_value=_make_result(skipped=["SECRET"]),
    ) as mock_sv:
        runner.invoke(
            run_cmd,
            [str(vault_file), "--identity", str(identity), "--skip", "SECRET"],
        )
    _, kwargs = mock_sv.call_args
    assert "SECRET" in kwargs.get("skip_keys", [])
