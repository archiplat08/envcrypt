"""Tests for envcrypt.env_backup."""

import json
import pytest
from pathlib import Path

from envcrypt.env_backup import (
    BackupError,
    BackupInfo,
    create_backup,
    list_backups,
    restore_backup,
    _backup_dir,
    _manifest_path,
)


@pytest.fixture
def vault_file(tmp_path: Path) -> Path:
    vf = tmp_path / "secrets.env.age"
    vf.write_bytes(b"encrypted-content")
    return vf


def test_create_backup_copies_vault(vault_file: Path) -> None:
    info = create_backup(vault_file)
    backup = Path(info.backup)
    assert backup.exists()
    assert backup.read_bytes() == vault_file.read_bytes()


def test_create_backup_returns_backup_info(vault_file: Path) -> None:
    info = create_backup(vault_file, note="pre-release")
    assert isinstance(info, BackupInfo)
    assert info.note == "pre-release"
    assert str(vault_file) == info.vault


def test_create_backup_records_in_manifest(vault_file: Path) -> None:
    create_backup(vault_file)
    manifest = json.loads(_manifest_path(vault_file).read_text())
    assert len(manifest) == 1
    assert manifest[0]["vault"] == str(vault_file)


def test_create_backup_multiple_entries(vault_file: Path) -> None:
    create_backup(vault_file, note="first")
    vault_file.write_bytes(b"updated-content")
    create_backup(vault_file, note="second")
    manifest = json.loads(_manifest_path(vault_file).read_text())
    assert len(manifest) == 2
    assert manifest[0]["note"] == "first"
    assert manifest[1]["note"] == "second"


def test_create_backup_missing_vault_raises(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="not found"):
        create_backup(tmp_path / "nonexistent.age")


def test_list_backups_returns_empty_when_no_manifest(vault_file: Path) -> None:
    assert list_backups(vault_file) == []


def test_list_backups_returns_all_entries(vault_file: Path) -> None:
    create_backup(vault_file, note="a")
    create_backup(vault_file, note="b")
    entries = list_backups(vault_file)
    assert len(entries) == 2
    assert all(isinstance(e, BackupInfo) for e in entries)


def test_list_backups_corrupt_manifest_raises(vault_file: Path) -> None:
    _manifest_path(vault_file).parent.mkdir(parents=True, exist_ok=True)
    _manifest_path(vault_file).write_text("not-json")
    with pytest.raises(BackupError, match="Corrupt"):
        list_backups(vault_file)


def test_restore_backup_overwrites_vault(vault_file: Path) -> None:
    info = create_backup(vault_file)
    vault_file.write_bytes(b"modified-content")
    restore_backup(Path(info.backup), vault_file)
    assert vault_file.read_bytes() == b"encrypted-content"


def test_restore_backup_missing_file_raises(vault_file: Path, tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="not found"):
        restore_backup(tmp_path / "ghost.age", vault_file)
