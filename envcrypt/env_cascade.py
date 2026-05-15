"""Cascade environment variables across multiple vault files with priority ordering."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.vault import encrypt_env_file


class CascadeError(Exception):
    """Raised when cascade operation fails."""


@dataclass
class CascadeResult:
    merged: Dict[str, str]
    sources: Dict[str, str]  # key -> which vault file it came from
    overridden: Dict[str, List[str]]  # key -> list of vaults that had it (lower priority first)

    def summary(self) -> str:
        total = len(self.merged)
        overridden = len(self.overridden)
        return f"{total} keys merged, {overridden} keys overridden across {len(set(self.sources.values()))} sources"


def cascade_vaults(
    vault_paths: List[Path],
    identity_path: Path,
    output_path: Path,
    recipients_path: Optional[Path] = None,
) -> CascadeResult:
    """Merge multiple vaults in priority order (last file wins).

    Args:
        vault_paths: Ordered list of vault files, later entries have higher priority.
        identity_path: Age identity file for decryption.
        output_path: Destination vault file for merged result.
        recipients_path: Recipients file for re-encryption.

    Returns:
        CascadeResult describing the merge.
    """
    if not vault_paths:
        raise CascadeError("At least one vault path is required.")

    merged: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    seen: Dict[str, List[str]] = {}

    for vault_path in vault_paths:
        if not vault_path.exists():
            raise CascadeError(f"Vault not found: {vault_path}")
        try:
            plaintext = decrypt(vault_path, identity_path)
        except Exception as exc:
            raise CascadeError(f"Failed to decrypt {vault_path}: {exc}") from exc

        env = parse_dotenv(plaintext)
        for key, value in env.items():
            seen.setdefault(key, [])
            seen[key].append(str(vault_path))
            merged[key] = value
            sources[key] = str(vault_path)

    overridden = {k: v for k, v in seen.items() if len(v) > 1}

    serialized = serialize_dotenv(merged)
    rp = recipients_path or vault_paths[0].parent / ".recipients"
    encrypt_env_file(output_path, serialized, rp)

    return CascadeResult(merged=merged, sources=sources, overridden=overridden)
