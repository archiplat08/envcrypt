"""Tests for envcrypt.env_access."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_access import (
    AccessError,
    AccessEntry,
    load_access_log,
    record_access,
    clear_access_log,
    filter_access_log,
    _access_log_path,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    v = tmp_path / "secrets.env.age"
    v.write_bytes(b"dummy")
    return v


def test_load_access_log_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_access_log(vault_file) == []


def test_access_log_placed_next_to_vault(vault_file: Path) -> None:
    expected = vault_file.parent / "secrets.access.json"
    assert _access_log_path(vault_file) == expected


def test_record_access_creates_log_file(vault_file: Path) -> None:
    record_access(vault_file, "read", "DB_PASSWORD", actor="alice")
    log_path = _access_log_path(vault_file)
    assert log_path.exists()


def test_record_access_stores_entry(vault_file: Path) -> None:
    entry = record_access(vault_file, "write", "API_KEY", actor="bob")
    assert entry.action == "write"
    assert entry.key == "API_KEY"
    assert entry.actor == "bob"
    assert entry.timestamp


def test_record_access_appends_multiple_entries(vault_file: Path) -> None:
    record_access(vault_file, "read", "KEY_A")
    record_access(vault_file, "write", "KEY_B")
    entries = load_access_log(vault_file)
    assert len(entries) == 2
    assert entries[0].key == "KEY_A"
    assert entries[1].key == "KEY_B"


def test_record_access_invalid_action_raises(vault_file: Path) -> None:
    with pytest.raises(AccessError, match="Invalid action"):
        record_access(vault_file, "hack", "KEY")


def test_record_access_omits_actor_when_none(vault_file: Path) -> None:
    entry = record_access(vault_file, "delete", "OLD_KEY")
    assert entry.actor is None
    assert "by" not in str(entry)


def test_clear_access_log_removes_file(vault_file: Path) -> None:
    record_access(vault_file, "read", "X")
    count = clear_access_log(vault_file)
    assert count == 1
    assert not _access_log_path(vault_file).exists()


def test_clear_access_log_returns_zero_when_no_file(vault_file: Path) -> None:
    assert clear_access_log(vault_file) == 0


def test_filter_by_action(vault_file: Path) -> None:
    record_access(vault_file, "read", "A")
    record_access(vault_file, "write", "B")
    results = filter_access_log(vault_file, action="read")
    assert len(results) == 1
    assert results[0].key == "A"


def test_filter_by_key(vault_file: Path) -> None:
    record_access(vault_file, "read", "DB_PASS")
    record_access(vault_file, "read", "API_KEY")
    results = filter_access_log(vault_file, key="API_KEY")
    assert len(results) == 1


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _access_log_path(vault_file).write_text("not-json")
    with pytest.raises(AccessError, match="Corrupt"):
        load_access_log(vault_file)


def test_entry_str_includes_actor(vault_file: Path) -> None:
    entry = record_access(vault_file, "read", "SECRET", actor="carol")
    assert "carol" in str(entry)
    assert "READ" in str(entry)
    assert "SECRET" in str(entry)
