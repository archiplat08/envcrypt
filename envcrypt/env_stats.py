"""Compute statistics about a vault's environment variables."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from envcrypt.vault import decrypt_env_file
from envcrypt.env_redact import _is_sensitive


class StatsError(Exception):
    """Raised when stats cannot be computed."""


@dataclass
class VaultStats:
    total_keys: int = 0
    sensitive_keys: int = 0
    empty_values: int = 0
    unique_prefixes: List[str] = field(default_factory=list)
    longest_key: str = ""
    longest_value_key: str = ""
    key_lengths: Dict[str, int] = field(default_factory=dict)

    @property
    def non_sensitive_keys(self) -> int:
        return self.total_keys - self.sensitive_keys

    def summary(self) -> str:
        lines = [
            f"Total keys      : {self.total_keys}",
            f"Sensitive keys  : {self.sensitive_keys}",
            f"Non-sensitive   : {self.non_sensitive_keys}",
            f"Empty values    : {self.empty_values}",
            f"Unique prefixes : {len(self.unique_prefixes)}",
            f"Longest key     : {self.longest_key or '(none)'}",
            f"Longest value   : {self.longest_value_key or '(none)'}",
        ]
        return "\n".join(lines)


def compute_stats(vault: Path, identity: Path) -> VaultStats:
    """Decrypt *vault* with *identity* and return a :class:`VaultStats`."""
    if not vault.exists():
        raise StatsError(f"Vault not found: {vault}")
    if not identity.exists():
        raise StatsError(f"Identity file not found: {identity}")

    env = decrypt_env_file(vault, identity)
    stats = VaultStats()
    stats.total_keys = len(env)

    prefix_set: set[str] = set()
    longest_key = ""
    longest_val_key = ""
    longest_val_len = -1

    for key, value in env.items():
        if _is_sensitive(key):
            stats.sensitive_keys += 1
        if value == "":
            stats.empty_values += 1

        if "_" in key:
            prefix_set.add(key.split("_")[0])

        if len(key) > len(longest_key):
            longest_key = key

        if len(value) > longest_val_len:
            longest_val_len = len(value)
            longest_val_key = key

        stats.key_lengths[key] = len(key)

    stats.unique_prefixes = sorted(prefix_set)
    stats.longest_key = longest_key
    stats.longest_value_key = longest_val_key
    return stats
