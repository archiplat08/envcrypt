"""Tests for the audit CLI commands."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from envcrypt.cli_audit import audit


@pytest.fixture
def runner():
    return CliRunner()


def _write_log(path: Path, entries: list):
    with path.open("w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def test_log_empty(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    result = runner.invoke(audit, ["log", "--log-file", str(log_file)])
    assert result.exit_code == 0
    assert "No audit log entries found" in result.output


def test_log_shows_entries(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    _write_log(log_file, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "file": ".env"},
        {"timestamp": "2024-01-01T01:00:00Z", "action": "decrypt", "file": ".env.age"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", str(log_file)])
    assert result.exit_code == 0
    assert "encrypt" in result.output
    assert "decrypt" in result.output


def test_log_filter_by_action(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    _write_log(log_file, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "file": ".env"},
        {"timestamp": "2024-01-01T01:00:00Z", "action": "decrypt", "file": ".env.age"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", str(log_file), "--action", "encrypt"])
    assert result.exit_code == 0
    assert "encrypt" in result.output
    assert "decrypt" not in result.output


def test_log_tail(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    entries = [
        {"timestamp": f"2024-01-01T0{i}:00:00Z", "action": "encrypt", "file": ".env"}
        for i in range(5)
    ]
    _write_log(log_file, entries)
    result = runner.invoke(audit, ["log", "--log-file", str(log_file), "--tail", "2"])
    assert result.exit_code == 0
    lines = [l for l in result.output.strip().splitlines() if l]
    assert len(lines) == 2


def test_log_shows_actor(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    _write_log(log_file, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "actor": "alice", "file": ".env"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", str(log_file)])
    assert result.exit_code == 0
    assert "actor=alice" in result.output


def test_clear_removes_log(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    _write_log(log_file, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "file": ".env"},
    ])
    result = runner.invoke(audit, ["clear", "--log-file", str(log_file)], input="y\n")
    assert result.exit_code == 0
    assert not log_file.exists()


def test_clear_no_file(runner, tmp_path):
    log_file = tmp_path / "audit.log"
    result = runner.invoke(audit, ["clear", "--log-file", str(log_file)], input="y\n")
    assert result.exit_code == 0
    assert "No audit log file found" in result.output
