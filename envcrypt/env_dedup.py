"""Deduplicate keys in a vault by removing entries with identical values."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class DedupError(Exception):
    """Raised when deduplication fails."""


@dataclass
class DedupResult:
    removed: List[str] = field(default_factory=list)
    kept: Dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.removed)

    def summary(self) -> str:
        if not self.removed:
            return "No duplicate values found."
        keys = ", ".join(self.removed)
        return f"Removed {self.count} duplicate key(s): {keys}"


def dedup_vault(
    vault_path: Path,
    identity_path: Path,
    *,
    output_path: Optional[Path] = None,
    dry_run: bool = False,
) -> DedupResult:
    """Remove keys whose values are duplicated by an earlier key (by insertion order).

    When multiple keys share the same value the first occurrence is kept and
    subsequent ones are removed.  The cleaned vault is re-encrypted in place
    (or to *output_path* when provided) unless *dry_run* is True.
    """
    if not vault_path.exists():
        raise DedupError(f"Vault not found: {vault_path}")

    try:
        plaintext = decrypt(vault_path, identity_path)
    except Exception as exc:  # pragma: no cover
        raise DedupError(f"Decryption failed: {exc}") from exc

    env = parse_dotenv(plaintext)

    seen_values: Dict[str, str] = {}  # value -> first key that had it
    kept: Dict[str, str] = {}
    removed: List[str] = []

    for key, value in env.items():
        if value in seen_values:
            removed.append(key)
        else:
            seen_values[value] = key
            kept[key] = value

    result = DedupResult(removed=removed, kept=kept)

    if removed and not dry_run:
        recipients = load_recipients(vault_path)
        if not recipients:
            raise DedupError("No recipients configured for vault.")
        cleaned = serialize_dotenv(kept)
        dest = output_path or vault_path
        try:
            encrypt(cleaned, dest, recipients)
        except Exception as exc:  # pragma: no cover
            raise DedupError(f"Encryption failed: {exc}") from exc

    return result
