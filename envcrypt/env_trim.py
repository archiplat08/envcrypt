"""Trim unused keys from a vault based on a reference schema file."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from envcrypt.dotenv import parse_dotenv
from envcrypt.vault import decrypt_env_file, encrypt_env_file


class TrimError(Exception):
    """Raised when trimming fails."""


@dataclass
class TrimResult:
    removed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.removed)

    def summary(self) -> str:
        if not self.removed:
            return "No keys removed — vault is already clean."
        removed_str = ", ".join(self.removed)
        return f"Removed {self.count} key(s): {removed_str}"


def trim_vault(
    vault_path: Path,
    schema_path: Path,
    identity_path: Path,
    recipients: Sequence[str],
    output_path: Path | None = None,
    dry_run: bool = False,
) -> TrimResult:
    """Remove keys from *vault_path* that are not present in *schema_path*.

    The schema file is a plain (unencrypted) .env file whose keys define the
    allowed set.  Values in the schema are ignored.
    """
    if not vault_path.exists():
        raise TrimError(f"Vault not found: {vault_path}")
    if not schema_path.exists():
        raise TrimError(f"Schema file not found: {schema_path}")
    if not identity_path.exists():
        raise TrimError(f"Identity file not found: {identity_path}")
    if not recipients:
        raise TrimError("At least one recipient is required.")

    env = decrypt_env_file(vault_path, identity_path)
    schema_raw = schema_path.read_text(encoding="utf-8")
    allowed_keys = set(parse_dotenv(schema_raw).keys())

    result = TrimResult()
    trimmed: dict[str, str] = {}
    for key, value in env.items():
        if key in allowed_keys:
            trimmed[key] = value
            result.kept.append(key)
        else:
            result.removed.append(key)

    if not dry_run and result.removed:
        dest = output_path or vault_path
        encrypt_env_file(trimmed, dest, list(recipients))

    return result
