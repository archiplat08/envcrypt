"""Time-to-live (TTL) management for vault keys."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional


class TtlError(Exception):
    """Raised when a TTL operation fails."""


def _ttl_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".ttl.json")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def load_ttl(vault_path: Path) -> Dict[str, str]:
    """Return mapping of key -> ISO expiry timestamp."""
    path = _ttl_path(vault_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise TtlError(f"Corrupt TTL file: {exc}") from exc


def save_ttl(vault_path: Path, ttl_map: Dict[str, str]) -> None:
    """Persist the TTL mapping next to the vault file."""
    _ttl_path(vault_path).write_text(json.dumps(ttl_map, indent=2))


def set_ttl(vault_path: Path, key: str, seconds: int) -> str:
    """Set a TTL for *key* and return the expiry timestamp string."""
    if seconds <= 0:
        raise TtlError("TTL must be a positive number of seconds.")
    expiry = _now_utc() + timedelta(seconds=seconds)
    expiry_iso = expiry.isoformat()
    ttl_map = load_ttl(vault_path)
    ttl_map[key] = expiry_iso
    save_ttl(vault_path, ttl_map)
    return expiry_iso


def remove_ttl(vault_path: Path, key: str) -> bool:
    """Remove the TTL for *key*. Returns True if an entry was removed."""
    ttl_map = load_ttl(vault_path)
    if key not in ttl_map:
        return False
    del ttl_map[key]
    save_ttl(vault_path, ttl_map)
    return True


def is_expired(vault_path: Path, key: str) -> bool:
    """Return True if *key* has a TTL that has already passed."""
    ttl_map = load_ttl(vault_path)
    if key not in ttl_map:
        return False
    expiry = datetime.fromisoformat(ttl_map[key])
    return _now_utc() >= expiry


def seconds_remaining(vault_path: Path, key: str) -> Optional[float]:
    """Return seconds until expiry, or None if no TTL is set. Negative means expired."""
    ttl_map = load_ttl(vault_path)
    if key not in ttl_map:
        return None
    expiry = datetime.fromisoformat(ttl_map[key])
    return (expiry - _now_utc()).total_seconds()


def list_ttl(vault_path: Path) -> Dict[str, str]:
    """Return all key -> expiry entries."""
    return load_ttl(vault_path)
