import json
import pytest
from click.testing import CliRunner
from pathlib import Path
from envcrypt.cli_audit import audit
from envcrypt.audit import record


@pytest.fixture
def runner():
    return CliRunner()


def _write_log(tmp_path, entries):
    log_file = tmp_path / "audit.log"
    for e in entries:
        with open(log_file, "a") as f:
            f.write(json.dumps(e) + "\n")
    return str(log_file)


def test_log_empty(runner, tmp_path):
    log_file = str(tmp_path / "audit.log")
    result = runner.invoke(audit, ["log", "--log-file", log_file])
    assert result.exit_code == 0
    assert "No audit log entries found" in result.output


def test_log_shows_entries(runner, tmp_path):
    log_file = _write_log(tmp_path, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "detail": ".env"},
        {"timestamp": "2024-01-02T00:00:00Z", "action": "decrypt", "detail": ".env", "actor": "alice"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", log_file])
    assert result.exit_code == 0
    assert "encrypt" in result.output
    assert "decrypt" in result.output
    assert "[alice]" in result.output


def test_log_filter_by_action(runner, tmp_path):
    log_file = _write_log(tmp_path, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "detail": ".env"},
        {"timestamp": "2024-01-02T00:00:00Z", "action": "decrypt", "detail": ".env"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", log_file, "--action", "encrypt"])
    assert result.exit_code == 0
    assert "encrypt" in result.output
    assert "decrypt" not in result.output


def test_log_filter_by_actor(runner, tmp_path):
    log_file = _write_log(tmp_path, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "detail": ".env", "actor": "bob"},
        {"timestamp": "2024-01-02T00:00:00Z", "action": "decrypt", "detail": ".env", "actor": "alice"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", log_file, "--actor", "bob"])
    assert result.exit_code == 0
    assert "bob" in result.output
    assert "alice" not in result.output


def test_log_as_json(runner, tmp_path):
    log_file = _write_log(tmp_path, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "detail": ".env"},
    ])
    result = runner.invoke(audit, ["log", "--log-file", log_file, "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert parsed[0]["action"] == "encrypt"


def test_clear_removes_log(runner, tmp_path):
    log_file = _write_log(tmp_path, [
        {"timestamp": "2024-01-01T00:00:00Z", "action": "encrypt", "detail": ".env"},
    ])
    result = runner.invoke(audit, ["clear", "--log-file", log_file], input="y\n")
    assert result.exit_code == 0
    assert "cleared" in result.output
    assert not Path(log_file).exists()


def test_clear_no_file(runner, tmp_path):
    log_file = str(tmp_path / "nonexistent.log")
    result = runner.invoke(audit, ["clear", "--log-file", log_file], input="y\n")
    assert result.exit_code == 0
    assert "No audit log file found" in result.output
