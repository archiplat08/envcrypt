"""Group management for env keys — assign keys to named groups and filter by group."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional


class GroupError(Exception):
    pass


def _groups_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".groups.json")


def load_groups(vault_path: Path) -> Dict[str, List[str]]:
    """Return mapping of group_name -> list of keys."""
    p = _groups_path(vault_path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise GroupError(f"Corrupt groups file: {exc}") from exc


def save_groups(vault_path: Path, groups: Dict[str, List[str]]) -> None:
    p = _groups_path(vault_path)
    p.write_text(json.dumps(groups, indent=2))


def add_key_to_group(vault_path: Path, group: str, key: str) -> Dict[str, List[str]]:
    """Add *key* to *group*, creating the group if necessary."""
    groups = load_groups(vault_path)
    members = groups.setdefault(group, [])
    if key not in members:
        members.append(key)
    save_groups(vault_path, groups)
    return groups


def remove_key_from_group(vault_path: Path, group: str, key: str) -> Dict[str, List[str]]:
    """Remove *key* from *group*. Raises GroupError if group or key not found."""
    groups = load_groups(vault_path)
    if group not in groups:
        raise GroupError(f"Group '{group}' does not exist.")
    if key not in groups[group]:
        raise GroupError(f"Key '{key}' is not in group '{group}'.")
    groups[group].remove(key)
    if not groups[group]:
        del groups[group]
    save_groups(vault_path, groups)
    return groups


def delete_group(vault_path: Path, group: str) -> None:
    """Delete an entire group."""
    groups = load_groups(vault_path)
    if group not in groups:
        raise GroupError(f"Group '{group}' does not exist.")
    del groups[group]
    save_groups(vault_path, groups)


def keys_in_group(vault_path: Path, group: str) -> List[str]:
    """Return the list of keys belonging to *group*."""
    groups = load_groups(vault_path)
    if group not in groups:
        raise GroupError(f"Group '{group}' does not exist.")
    return list(groups[group])


def groups_for_key(vault_path: Path, key: str) -> List[str]:
    """Return all groups that contain *key*."""
    groups = load_groups(vault_path)
    return [g for g, members in groups.items() if key in members]
