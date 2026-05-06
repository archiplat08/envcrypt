"""Backup and restore encrypted vault files."""

from __future__ import annotations

import shutil
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


class BackupError(Exception):
    """Raised when a backup or restore operation fails."""


@dataclass
class BackupInfo:
    vault: str
    backup: str
    created_at: str
    note: str


def _backup_dir(vault_path: Path) -> Path:
    return vault_path.parent / ".envcrypt_backups"


def _manifest_path(vault_path: Path) -> Path:
    return _backup_dir(vault_path) / "manifest.json"


def _load_manifest(vault_path: Path) -> list[dict]:
    mp = _manifest_path(vault_path)
    if not mp.exists():
        return []
    try:
        return json.loads(mp.read_text())
    except json.JSONDecodeError as exc:
        raise BackupError(f"Corrupt backup manifest: {exc}") from exc


def _save_manifest(vault_path: Path, entries: list[dict]) -> None:
    mp = _manifest_path(vault_path)
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text(json.dumps(entries, indent=2))


def create_backup(vault_path: Path, note: str = "") -> BackupInfo:
    """Copy the vault to the backup directory and record it in the manifest."""
    vault_path = Path(vault_path)
    if not vault_path.exists():
        raise BackupError(f"Vault file not found: {vault_path}")

    backup_dir = _backup_dir(vault_path)
    backup_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_name = f"{vault_path.stem}_{ts}{vault_path.suffix}"
    backup_path = backup_dir / backup_name

    shutil.copy2(vault_path, backup_path)

    entry = BackupInfo(
        vault=str(vault_path),
        backup=str(backup_path),
        created_at=datetime.now(timezone.utc).isoformat(),
        note=note,
    )
    manifest = _load_manifest(vault_path)
    manifest.append(asdict(entry))
    _save_manifest(vault_path, manifest)
    return entry


def list_backups(vault_path: Path) -> list[BackupInfo]:
    """Return all recorded backups for the given vault."""
    return [BackupInfo(**e) for e in _load_manifest(Path(vault_path))]


def restore_backup(backup_path: Path, vault_path: Path) -> None:
    """Overwrite the vault with the given backup file."""
    backup_path = Path(backup_path)
    vault_path = Path(vault_path)
    if not backup_path.exists():
        raise BackupError(f"Backup file not found: {backup_path}")
    shutil.copy2(backup_path, vault_path)
