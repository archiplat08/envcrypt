"""Tag and filter vault entries by environment (e.g. dev, staging, prod)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

TAGS_SUFFIX = ".tags.json"


class TagError(Exception):
    """Raised when a tagging operation fails."""


def _tags_path(vault_path: Path) -> Path:
    return vault_path.with_name(vault_path.name + TAGS_SUFFIX)


def load_tags(vault_path: Path) -> Dict[str, List[str]]:
    """Return mapping of key -> list[tag] for the given vault."""
    path = _tags_path(vault_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise TagError(f"Corrupt tags file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise TagError(f"Tags file {path} must contain a JSON object")
    return {k: list(v) for k, v in data.items()}


def save_tags(vault_path: Path, tags: Dict[str, List[str]]) -> None:
    """Persist the key->tags mapping next to the vault file."""
    path = _tags_path(vault_path)
    path.write_text(json.dumps(tags, indent=2))


def tag_key(vault_path: Path, key: str, tag: str) -> Dict[str, List[str]]:
    """Add *tag* to *key* in the vault's tag mapping."""
    tags = load_tags(vault_path)
    entry = tags.setdefault(key, [])
    if tag not in entry:
        entry.append(tag)
    save_tags(vault_path, tags)
    return tags


def untag_key(vault_path: Path, key: str, tag: str) -> Dict[str, List[str]]:
    """Remove *tag* from *key*; silently ignores missing tag."""
    tags = load_tags(vault_path)
    if key in tags:
        tags[key] = [t for t in tags[key] if t != tag]
        if not tags[key]:
            del tags[key]
    save_tags(vault_path, tags)
    return tags


def filter_keys_by_tag(
    vault_path: Path,
    env_keys: Dict[str, str],
    tag: str,
    *,
    untagged: bool = False,
) -> Dict[str, str]:
    """Return subset of *env_keys* whose tag mapping includes *tag*.

    If *untagged* is True, return keys that have NO tags at all instead.
    """
    tags = load_tags(vault_path)
    if untagged:
        return {k: v for k, v in env_keys.items() if k not in tags or not tags[k]}
    return {k: v for k, v in env_keys.items() if tag in tags.get(k, [])}
