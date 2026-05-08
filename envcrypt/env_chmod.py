"""Permission/access control for vault keys — restrict which recipients can see which keys."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


class ChmodError(Exception):
    """Raised when a permission operation fails."""


@dataclass
class KeyPermission:
    key: str
    allowed_recipients: List[str] = field(default_factory=list)
    deny_all: bool = False


def _perms_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".perms.json")


def load_permissions(vault_path: Path) -> Dict[str, KeyPermission]:
    """Load key permissions from the sidecar .perms.json file."""
    path = _perms_path(vault_path)
    if not path.exists():
        return {}
    try:
        raw: dict = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ChmodError(f"Corrupt permissions file: {exc}") from exc
    result: Dict[str, KeyPermission] = {}
    for key, entry in raw.items():
        result[key] = KeyPermission(
            key=key,
            allowed_recipients=entry.get("allowed_recipients", []),
            deny_all=entry.get("deny_all", False),
        )
    return result


def save_permissions(vault_path: Path, perms: Dict[str, KeyPermission]) -> None:
    """Persist permissions to the sidecar file."""
    path = _perms_path(vault_path)
    raw = {
        key: {
            "allowed_recipients": perm.allowed_recipients,
            "deny_all": perm.deny_all,
        }
        for key, perm in perms.items()
    }
    path.write_text(json.dumps(raw, indent=2))


def set_permission(
    vault_path: Path,
    key: str,
    allowed_recipients: Optional[List[str]] = None,
    deny_all: bool = False,
) -> KeyPermission:
    """Set access control for a single key."""
    if not vault_path.exists():
        raise ChmodError(f"Vault not found: {vault_path}")
    perms = load_permissions(vault_path)
    perm = KeyPermission(
        key=key,
        allowed_recipients=list(allowed_recipients or []),
        deny_all=deny_all,
    )
    perms[key] = perm
    save_permissions(vault_path, perms)
    return perm


def remove_permission(vault_path: Path, key: str) -> bool:
    """Remove access restrictions for a key. Returns True if entry existed."""
    perms = load_permissions(vault_path)
    if key not in perms:
        return False
    del perms[key]
    save_permissions(vault_path, perms)
    return True


def is_allowed(vault_path: Path, key: str, recipient: str) -> bool:
    """Return True if recipient is allowed to access key (open by default)."""
    perms = load_permissions(vault_path)
    if key not in perms:
        return True
    perm = perms[key]
    if perm.deny_all:
        return False
    if perm.allowed_recipients:
        return recipient in perm.allowed_recipients
    return True
