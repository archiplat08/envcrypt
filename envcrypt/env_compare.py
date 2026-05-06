"""Compare two encrypted vault files and report differences."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv
from envcrypt.diff import diff_envs, format_diff, DiffEntry


class CompareError(Exception):
    """Raised when vault comparison fails."""


@dataclass
class CompareResult:
    entries: list[DiffEntry] = field(default_factory=list)
    vault_a: str = ""
    vault_b: str = ""

    @property
    def has_differences(self) -> bool:
        return any(e.status != "unchanged" for e in self.entries)

    @property
    def summary(self) -> str:
        added = sum(1 for e in self.entries if e.status == "added")
        removed = sum(1 for e in self.entries if e.status == "removed")
        changed = sum(1 for e in self.entries if e.status == "changed")
        return f"+{added} -{removed} ~{changed}"


def compare_vaults(
    vault_a: Path,
    vault_b: Path,
    identity: Path,
    show_values: bool = False,
    show_unchanged: bool = False,
) -> CompareResult:
    """Decrypt two vault files and return a structured diff."""
    if not vault_a.exists():
        raise CompareError(f"Vault not found: {vault_a}")
    if not vault_b.exists():
        raise CompareError(f"Vault not found: {vault_b}")
    if not identity.exists():
        raise CompareError(f"Identity file not found: {identity}")

    try:
        raw_a = decrypt(vault_a, identity)
        env_a = parse_dotenv(raw_a)
    except Exception as exc:
        raise CompareError(f"Failed to decrypt {vault_a}: {exc}") from exc

    try:
        raw_b = decrypt(vault_b, identity)
        env_b = parse_dotenv(raw_b)
    except Exception as exc:
        raise CompareError(f"Failed to decrypt {vault_b}: {exc}") from exc

    entries = diff_envs(env_a, env_b, show_values=show_values)
    if not show_unchanged:
        entries = [e for e in entries if e.status != "unchanged"]

    return CompareResult(
        entries=entries,
        vault_a=str(vault_a),
        vault_b=str(vault_b),
    )
