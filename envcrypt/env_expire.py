"""Expiry tracking for vault secrets."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class ExpireError(Exception):
    """Raised when an expiry operation fails."""


@dataclass
class ExpiryInfo:
    key: str
    expires_at: str  # ISO-8601
    note: str = ""

    def is_expired(self) -> bool:
        expiry = datetime.fromisoformat(self.expires_at)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return datetime.now(tz=timezone.utc) >= expiry

    def days_remaining(self) -> float:
        expiry = datetime.fromisoformat(self.expires_at)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(tz=timezone.utc)
        return delta.total_seconds() / 86400


def _expiry_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".expiry.json")


def load_expiry(vault_path: Path) -> Dict[str, ExpiryInfo]:
    path = _expiry_path(vault_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ExpireError(f"Corrupt expiry file: {exc}") from exc
    return {
        k: ExpiryInfo(key=k, expires_at=v["expires_at"], note=v.get("note", ""))
        for k, v in data.items()
    }


def save_expiry(vault_path: Path, expiry_map: Dict[str, ExpiryInfo]) -> None:
    path = _expiry_path(vault_path)
    data = {
        k: {"expires_at": v.expires_at, "note": v.note}
        for k, v in expiry_map.items()
    }
    path.write_text(json.dumps(data, indent=2))


def set_expiry(vault_path: Path, key: str, expires_at: str, note: str = "") -> ExpiryInfo:
    """Set or update expiry for a key."""
    try:
        datetime.fromisoformat(expires_at)
    except ValueError as exc:
        raise ExpireError(f"Invalid date format '{expires_at}': {exc}") from exc
    expiry_map = load_expiry(vault_path)
    info = ExpiryInfo(key=key, expires_at=expires_at, note=note)
    expiry_map[key] = info
    save_expiry(vault_path, expiry_map)
    return info


def remove_expiry(vault_path: Path, key: str) -> bool:
    """Remove expiry for a key. Returns True if it existed."""
    expiry_map = load_expiry(vault_path)
    if key not in expiry_map:
        return False
    del expiry_map[key]
    save_expiry(vault_path, expiry_map)
    return True


def list_expired(vault_path: Path) -> List[ExpiryInfo]:
    """Return all keys whose expiry has passed."""
    return [info for info in load_expiry(vault_path).values() if info.is_expired()]
