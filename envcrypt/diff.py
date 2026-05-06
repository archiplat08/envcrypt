"""Utilities to diff two .env files or a plaintext vs decrypted vault."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from envcrypt.dotenv import parse_dotenv


@dataclass
class DiffEntry:
    key: str
    status: str  # 'added' | 'removed' | 'changed' | 'unchanged'
    old_value: str | None = None
    new_value: str | None = None


def diff_envs(
    old: Dict[str, str],
    new: Dict[str, str],
    *,
    show_unchanged: bool = False,
) -> List[DiffEntry]:
    """Compare two env dicts and return a list of DiffEntry results."""
    entries: List[DiffEntry] = []
    all_keys = sorted(set(old) | set(new))

    for key in all_keys:
        if key in old and key not in new:
            entries.append(DiffEntry(key=key, status="removed", old_value=old[key]))
        elif key not in old and key in new:
            entries.append(DiffEntry(key=key, status="added", new_value=new[key]))
        elif old[key] != new[key]:
            entries.append(
                DiffEntry(
                    key=key,
                    status="changed",
                    old_value=old[key],
                    new_value=new[key],
                )
            )
        elif show_unchanged:
            entries.append(
                DiffEntry(
                    key=key,
                    status="unchanged",
                    old_value=old[key],
                    new_value=new[key],
                )
            )

    return entries


def diff_env_files(
    old_path: str,
    new_path: str,
    *,
    show_unchanged: bool = False,
) -> List[DiffEntry]:
    """Parse two .env files from disk and return their diff."""
    with open(old_path, "r", encoding="utf-8") as fh:
        old = parse_dotenv(fh.read())
    with open(new_path, "r", encoding="utf-8") as fh:
        new = parse_dotenv(fh.read())
    return diff_envs(old, new, show_unchanged=show_unchanged)


def format_diff(entries: List[DiffEntry], *, mask_values: bool = True) -> str:
    """Return a human-readable diff string."""
    lines: List[str] = []
    symbols = {"added": "+", "removed": "-", "changed": "~", "unchanged": " "}

    for entry in entries:
        sym = symbols[entry.status]
        if entry.status == "added":
            val = "***" if mask_values else entry.new_value
            lines.append(f"{sym} {entry.key}={val}")
        elif entry.status == "removed":
            val = "***" if mask_values else entry.old_value
            lines.append(f"{sym} {entry.key}={val}")
        elif entry.status == "changed":
            if mask_values:
                lines.append(f"{sym} {entry.key}=*** -> ***")
            else:
                lines.append(f"{sym} {entry.key}={entry.old_value} -> {entry.new_value}")
        else:
            val = "***" if mask_values else entry.old_value
            lines.append(f"{sym} {entry.key}={val}")

    return "\n".join(lines)
