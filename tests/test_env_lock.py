"""Tests for envcrypt.env_lock."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_lock import (
    LockError,
    is_locked,
    lock_vault,
    read_lock_info,
    unlock_vault,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_text("encrypted-content")
    return p


def test_is_locked_returns_false_when_no_lock(vault_file: Path) -> None:
    assert is_locked(vault_file) is False


def test_lock_creates_lock_file(vault_file: Path) -> None:
    lock_vault(vault_file)
    assert is_locked(vault_file) is True


def test_lock_returns_lock_info(vault_file: Path) -> None:
    info = lock_vault(vault_file, actor="alice@example.com")
    assert info.locked_by == "alice@example.com"
    assert info.vault == str(vault_file)
    assert info.locked_at  # non-empty timestamp


def test_lock_without_actor(vault_file: Path) -> None:
    info = lock_vault(vault_file)
    assert info.locked_by is None


def test_lock_missing_vault_raises(tmp_path: Path) -> None:
    missing = tmp_path / "ghost.env.age"
    with pytest.raises(LockError, match="Vault not found"):
        lock_vault(missing)


def test_lock_already_locked_raises(vault_file: Path) -> None:
    lock_vault(vault_file)
    with pytest.raises(LockError, match="already locked"):
        lock_vault(vault_file)


def test_unlock_removes_lock_file(vault_file: Path) -> None:
    lock_vault(vault_file)
    unlock_vault(vault_file)
    assert is_locked(vault_file) is False


def test_unlock_not_locked_raises(vault_file: Path) -> None:
    with pytest.raises(LockError, match="not locked"):
        unlock_vault(vault_file)


def test_read_lock_info_returns_metadata(vault_file: Path) -> None:
    lock_vault(vault_file, actor="bob")
    info = read_lock_info(vault_file)
    assert info.locked_by == "bob"


def test_read_lock_info_not_locked_raises(vault_file: Path) -> None:
    with pytest.raises(LockError, match="not locked"):
        read_lock_info(vault_file)


def test_read_lock_info_corrupt_file_raises(vault_file: Path) -> None:
    lock_file = vault_file.with_suffix(vault_file.suffix + ".lock")
    lock_file.write_text("not-json")
    with pytest.raises(LockError, match="Corrupt lock file"):
        read_lock_info(vault_file)
