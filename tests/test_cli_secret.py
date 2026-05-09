"""Tests for envcrypt.cli_secret."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_secret import secret
from envcrypt.env_secret import SecretError, SecretFinding, SecretScanResult


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text("DEBUG=true\n")
    return p


def _clean_result() -> SecretScanResult:
    return SecretScanResult()


def _dirty_result() -> SecretScanResult:
    return SecretScanResult(
        findings=[SecretFinding(key="API_KEY", reason="matches hex pattern")]
    )


def test_scan_clean_prints_ok(runner, env_file):
    with patch("envcrypt.cli_secret.scan_env_file", return_value=_clean_result()):
        result = runner.invoke(secret, ["scan", str(env_file)])
    assert result.exit_code == 0
    assert "No secrets" in result.output


def test_scan_findings_printed(runner, env_file):
    with patch("envcrypt.cli_secret.scan_env_file", return_value=_dirty_result()):
        result = runner.invoke(secret, ["scan", str(env_file)])
    assert result.exit_code == 0
    assert "API_KEY" in result.output
    assert "WARN" in result.output


def test_scan_strict_exits_nonzero_on_findings(runner, env_file):
    with patch("envcrypt.cli_secret.scan_env_file", return_value=_dirty_result()):
        result = runner.invoke(secret, ["scan", "--strict", str(env_file)])
    assert result.exit_code != 0


def test_scan_strict_exits_zero_when_clean(runner, env_file):
    with patch("envcrypt.cli_secret.scan_env_file", return_value=_clean_result()):
        result = runner.invoke(secret, ["scan", "--strict", str(env_file)])
    assert result.exit_code == 0


def test_scan_error_exits_nonzero(runner, env_file):
    with patch(
        "envcrypt.cli_secret.scan_env_file",
        side_effect=SecretError("file not found"),
    ):
        result = runner.invoke(secret, ["scan", str(env_file)])
    assert result.exit_code != 0
    assert "Error" in result.output
