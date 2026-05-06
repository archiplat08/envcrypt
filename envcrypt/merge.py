"""Merge two .env vault files, with configurable conflict resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class ConflictStrategy(str, Enum):
    OURS = "ours"       # keep value from base vault
    THEIRS = "theirs"   # keep value from other vault
    ERROR = "error"     # raise on any conflict


class MergeError(Exception):
    """Raised when merge cannot be completed."""


@dataclass
class MergeResult:
    merged: Dict[str, str]
    conflicts: List[str] = field(default_factory=list)
    added_keys: List[str] = field(default_factory=list)
    removed_keys: List[str] = field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        """Return True if any conflicting keys were encountered during merge."""
        return bool(self.conflicts)

    def summary(self) -> str:
        """Return a human-readable summary of the merge result."""
        lines = [
            f"Merged keys : {len(self.merged)}",
            f"Added       : {len(self.added_keys)} {self.added_keys}",
            f"Removed     : {len(self.removed_keys)} {self.removed_keys}",
            f"Conflicts   : {len(self.conflicts)} {self.conflicts}",
        ]
        return "\n".join(lines)


def merge_envs(
    base: Dict[str, str],
    other: Dict[str, str],
    strategy: ConflictStrategy = ConflictStrategy.OURS,
) -> MergeResult:
    """Merge two env dicts according to *strategy*."""
    result: Dict[str, str] = dict(base)
    conflicts: List[str] = []
    added_keys: List[str] = []

    for key, value in other.items():
        if key not in base:
            result[key] = value
            added_keys.append(key)
        elif base[key] != value:
            conflicts.append(key)
            if strategy == ConflictStrategy.ERROR:
                raise MergeError(
                    f"Conflict on key '{key}': base={base[key]!r}, other={value!r}"
                )
            elif strategy == ConflictStrategy.THEIRS:
                result[key] = value
            # OURS: keep base value (already in result)

    removed_keys = [k for k in base if k not in other]
    return MergeResult(
        merged=result,
        conflicts=conflicts,
        added_keys=added_keys,
        removed_keys=removed_keys,
    )


def merge_vault_files(
    base_vault: Path,
    other_vault: Path,
    identity_file: Path,
    output: Optional[Path] = None,
    recipients_file: Optional[Path] = None,
    strategy: ConflictStrategy = ConflictStrategy.OURS,
) -> MergeResult:
    """Decrypt both vaults, merge them, and re-encrypt into *output*."""
    base_plain = decrypt(base_vault, identity_file)
    other_plain = decrypt(other_vault, identity_file)

    base_env = parse_dotenv(base_plain)
    other_env = parse_dotenv(other_plain)

    merge_result = merge_envs(base_env, other_env, strategy=strategy)

    recipients_path = recipients_file or base_vault.parent / ".recipients"
    recipients = load_recipients(recipients_path)
    if not recipients:
        raise MergeError("No recipients found; cannot re-encrypt merged vault.")

    merged_text = serialize_dotenv(merge_result.merged)
    out_path = output or base_vault
    encrypt(merged_text, out_path, recipients)

    return merge_result
