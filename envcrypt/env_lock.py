"""Lock/unlock a vault to prevent accidental modifications."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


LOCK_SUFFIX = ".lock"


class LockError(Exception):
    """Raised when a lock operation fails."""


@dataclass
class LockInfo:
    vault: str
    locked_by: str | None
    locked_at: str


def _lock_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(vault_path.suffix + LOCK_SUFFIX)


def is_locked(vault_path: Path) -> bool:
    """Return True if the vault has an associated lock file."""
    return _lock_path(vault_path).exists()


def lock_vault(vault_path: Path, actor: str | None = None) -> LockInfo:
    """Create a lock file for *vault_path*.

    Raises LockError if the vault is already locked or does not exist.
    """
    if not vault_path.exists():
        raise LockError(f"Vault not found: {vault_path}")
    lock_file = _lock_path(vault_path)
    if lock_file.exists():
        raise LockError(f"Vault is already locked: {vault_path}")

    from envcrypt.audit import _now_iso  # local import to avoid cycles

    info = LockInfo(
        vault=str(vault_path),
        locked_by=actor,
        locked_at=_now_iso(),
    )
    lock_file.write_text(
        json.dumps({"vault": info.vault, "locked_by": info.locked_by, "locked_at": info.locked_at})
    )
    return info


def unlock_vault(vault_path: Path) -> None:
    """Remove the lock file for *vault_path*.

    Raises LockError if the vault is not locked.
    """
    lock_file = _lock_path(vault_path)
    if not lock_file.exists():
        raise LockError(f"Vault is not locked: {vault_path}")
    lock_file.unlink()


def read_lock_info(vault_path: Path) -> LockInfo:
    """Return metadata stored in the lock file.

    Raises LockError if the vault is not locked.
    """
    lock_file = _lock_path(vault_path)
    if not lock_file.exists():
        raise LockError(f"Vault is not locked: {vault_path}")
    try:
        data = json.loads(lock_file.read_text())
    except json.JSONDecodeError as exc:
        raise LockError(f"Corrupt lock file: {lock_file}") from exc
    return LockInfo(
        vault=data.get("vault", str(vault_path)),
        locked_by=data.get("locked_by"),
        locked_at=data.get("locked_at", ""),
    )
