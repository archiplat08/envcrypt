"""Track encrypted vault snapshots for rollback support."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

HISTORY_DIR = ".envcrypt_history"


class HistoryError(Exception):
    pass


@dataclass
class Snapshot:
    index: int
    timestamp: str
    vault_path: str
    snapshot_file: str
    note: Optional[str] = None


def _history_dir(vault_path: Path) -> Path:
    return vault_path.parent / HISTORY_DIR / vault_path.stem


def _index_file(vault_path: Path) -> Path:
    return _history_dir(vault_path) / "index.json"


def _load_index(vault_path: Path) -> List[dict]:
    idx = _index_file(vault_path)
    if not idx.exists():
        return []
    return json.loads(idx.read_text())


def _save_index(vault_path: Path, entries: List[dict]) -> None:
    idx = _index_file(vault_path)
    idx.parent.mkdir(parents=True, exist_ok=True)
    idx.write_text(json.dumps(entries, indent=2))


def save_snapshot(vault_path: Path, note: Optional[str] = None) -> Snapshot:
    """Copy the current vault file into history and record metadata."""
    vault_path = vault_path.resolve()
    if not vault_path.exists():
        raise HistoryError(f"Vault file not found: {vault_path}")

    entries = _load_index(vault_path)
    index = len(entries)
    ts = datetime.now(timezone.utc).isoformat()
    dest_dir = _history_dir(vault_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    snapshot_file = str(dest_dir / f"{index:04d}.age")
    shutil.copy2(vault_path, snapshot_file)

    entry = {
        "index": index,
        "timestamp": ts,
        "vault_path": str(vault_path),
        "snapshot_file": snapshot_file,
        "note": note,
    }
    entries.append(entry)
    _save_index(vault_path, entries)
    return Snapshot(**entry)


def list_snapshots(vault_path: Path) -> List[Snapshot]:
    """Return all recorded snapshots for a vault file."""
    return [Snapshot(**e) for e in _load_index(vault_path.resolve())]


def restore_snapshot(vault_path: Path, index: int) -> Snapshot:
    """Overwrite the vault file with a previously saved snapshot."""
    vault_path = vault_path.resolve()
    entries = _load_index(vault_path)
    if not entries:
        raise HistoryError("No snapshots found.")
    matches = [e for e in entries if e["index"] == index]
    if not matches:
        raise HistoryError(f"Snapshot {index} not found.")
    snap = Snapshot(**matches[0])
    if not Path(snap.snapshot_file).exists():
        raise HistoryError(f"Snapshot file missing: {snap.snapshot_file}")
    shutil.copy2(snap.snapshot_file, vault_path)
    return snap
