import json
import pytest
from pathlib import Path
from envcrypt.audit import record, read_log, AUDIT_LOG_FILE


def test_record_creates_log_file(tmp_path):
    log = tmp_path / "audit.log"
    entry = record("encrypt", "encrypted .env", log_path=log)
    assert log.exists()
    assert entry["operation"] == "encrypt"
    assert entry["detail"] == "encrypted .env"
    assert "timestamp" in entry


def test_record_appends_multiple_entries(tmp_path):
    log = tmp_path / "audit.log"
    record("encrypt", "first", log_path=log)
    record("decrypt", "second", log_path=log)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["operation"] == "encrypt"
    assert second["operation"] == "decrypt"


def test_record_includes_actor_when_provided(tmp_path):
    log = tmp_path / "audit.log"
    entry = record("key_generate", "generated key", log_path=log, actor="alice")
    assert entry["actor"] == "alice"
    saved = json.loads(log.read_text().strip())
    assert saved["actor"] == "alice"


def test_record_omits_actor_when_not_provided(tmp_path):
    log = tmp_path / "audit.log"
    entry = record("recipient_add", "added bob", log_path=log)
    assert "actor" not in entry


def test_read_log_returns_empty_list_when_no_file(tmp_path):
    log = tmp_path / "nonexistent.log"
    assert read_log(log_path=log) == []


def test_read_log_returns_all_entries(tmp_path):
    log = tmp_path / "audit.log"
    record("encrypt", "a", log_path=log)
    record("decrypt", "b", log_path=log)
    record("recipient_remove", "c", log_path=log)
    entries = read_log(log_path=log)
    assert len(entries) == 3
    assert entries[2]["operation"] == "recipient_remove"


def test_read_log_ignores_blank_lines(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text('{"timestamp": "t", "operation": "encrypt", "detail": "x"}\n\n\n')
    entries = read_log(log_path=log)
    assert len(entries) == 1
