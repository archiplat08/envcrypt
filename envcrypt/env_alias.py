"""Manage key aliases in a vault — map friendly names to real env keys."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional


class AliasError(Exception):
    """Raised when an alias operation fails."""


def _aliases_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".aliases.json")


def load_aliases(vault_path: Path) -> Dict[str, str]:
    """Return alias -> real_key mapping for *vault_path*.

    Returns an empty dict when no alias file exists.
    """
    path = _aliases_path(vault_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise AliasError(f"Corrupt alias file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AliasError(f"Alias file {path} must contain a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def save_aliases(vault_path: Path, aliases: Dict[str, str]) -> None:
    """Persist *aliases* next to *vault_path*."""
    path = _aliases_path(vault_path)
    path.write_text(json.dumps(aliases, indent=2) + "\n")


def set_alias(vault_path: Path, alias: str, real_key: str) -> Dict[str, str]:
    """Add or update *alias* -> *real_key* and return the updated mapping."""
    if not alias:
        raise AliasError("Alias name must not be empty")
    if not real_key:
        raise AliasError("Real key name must not be empty")
    aliases = load_aliases(vault_path)
    aliases[alias] = real_key
    save_aliases(vault_path, aliases)
    return aliases


def remove_alias(vault_path: Path, alias: str) -> Dict[str, str]:
    """Remove *alias* and return the updated mapping.

    Raises :class:`AliasError` when the alias does not exist.
    """
    aliases = load_aliases(vault_path)
    if alias not in aliases:
        raise AliasError(f"Alias '{alias}' not found")
    del aliases[alias]
    save_aliases(vault_path, aliases)
    return aliases


def resolve_alias(vault_path: Path, name: str) -> str:
    """Return the real key for *name*, or *name* itself if no alias exists."""
    aliases = load_aliases(vault_path)
    return aliases.get(name, name)
