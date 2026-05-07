"""Filter vault entries by key pattern, tag, or prefix."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.env_tag import load_tags


class FilterError(Exception):
    """Raised when filtering fails."""


@dataclass
class FilterResult:
    matched: Dict[str, str] = field(default_factory=dict)
    excluded: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.matched)

    def summary(self) -> str:
        return f"{self.count} key(s) matched, {len(self.excluded)} excluded"


def filter_env(
    env: Dict[str, str],
    *,
    pattern: Optional[str] = None,
    prefix: Optional[str] = None,
    tags: Optional[List[str]] = None,
    tag_map: Optional[Dict[str, List[str]]] = None,
) -> FilterResult:
    """Filter an env dict by glob pattern, prefix, or tags."""
    result = FilterResult()
    tag_map = tag_map or {}

    for key, value in env.items():
        if prefix and not key.startswith(prefix):
            result.excluded.append(key)
            continue
        if pattern and not fnmatch.fnmatch(key, pattern):
            result.excluded.append(key)
            continue
        if tags:
            key_tags = tag_map.get(key, [])
            if not any(t in key_tags for t in tags):
                result.excluded.append(key)
                continue
        result.matched[key] = value

    return result


def filter_vault(
    vault_file: Path,
    identity_file: Path,
    *,
    pattern: Optional[str] = None,
    prefix: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> FilterResult:
    """Decrypt a vault and return a filtered view of its contents."""
    if not vault_file.exists():
        raise FilterError(f"Vault file not found: {vault_file}")
    if not identity_file.exists():
        raise FilterError(f"Identity file not found: {identity_file}")

    try:
        plaintext = decrypt(vault_file, identity_file)
    except Exception as exc:
        raise FilterError(f"Failed to decrypt vault: {exc}") from exc

    env = parse_dotenv(plaintext)
    tag_map: Dict[str, List[str]] = {}
    if tags:
        try:
            tag_map = load_tags(vault_file)
        except Exception:
            tag_map = {}

    return filter_env(env, pattern=pattern, prefix=prefix, tags=tags, tag_map=tag_map)
