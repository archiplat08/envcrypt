"""Tests for envcrypt.env_history."""
import json
from pathlib import Path

import pytest

from envcrypt.env_history import (
    HistoryError,
    save_snapshot,
    list_snapshots,
    restore_snapshot,
    HISTORY_DIR,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.age"
    p.write_text("encrypted-content-v1")
    return p


def test_save_snapshot_creates_snapshot_file(vault_file: Path) -> None:
    snap = save_snapshot(vault_file)
    assert snap.index == 0
    assert Path(snap.snapshot_file).exists()
    assert Path(snap.snapshot_file).read_text() == "encrypted-content-v1"


def test_save_snapshot_increments_index(vault_file: Path) -> None:
    snap1 = save_snapshot(vault_file)
    snap2 = save_snapshot(vault_file)
    assert snap1.index == 0
    assert snap2.index == 1


def test_save_snapshot_stores_note(vault_file: Path) -> None:
    snap = save_snapshot(vault_file, note="before rotation")
    assert snap.note == "before rotation"


def test_save_snapshot_missing_vault_raises(tmp_path: Path) -> None:
    with pytest.raises(HistoryError, match="not found"):
        save_snapshot(tmp_path / "ghost.age")


def test_list_snapshots_empty_when_no_history(vault_file: Path) -> None:
    assert list_snapshots(vault_file) == []


def test_list_snapshots_returns_all_entries(vault_file: Path) -> None:
    save_snapshot(vault_file, note="first")
    save_snapshot(vault_file, note="second")
    snaps = list_snapshots(vault_file)
    assert len(snaps) == 2
    assert snaps[0].note == "first"
    assert snaps[1].note == "second"


def test_restore_snapshot_overwrites_vault(vault_file: Path) -> None:
    save_snapshot(vault_file)  # snapshot 0 has v1
    vault_file.write_text("encrypted-content-v2")
    restore_snapshot(vault_file, 0)
    assert vault_file.read_text() == "encrypted-content-v1"


def test_restore_snapshot_unknown_index_raises(vault_file: Path) -> None:
    save_snapshot(vault_file)
    with pytest.raises(HistoryError, match="not found"):
        restore_snapshot(vault_file, 99)


def test_restore_snapshot_no_history_raises(vault_file: Path) -> None:
    with pytest.raises(HistoryError, match="No snapshots"):
        restore_snapshot(vault_file, 0)


def test_index_file_is_valid_json(vault_file: Path) -> None:
    save_snapshot(vault_file)
    idx_file = vault_file.parent / HISTORY_DIR / vault_file.stem / "index.json"
    data = json.loads(idx_file.read_text())
    assert isinstance(data, list)
    assert data[0]["index"] == 0
