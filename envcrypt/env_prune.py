"""Remove unused or stale keys from a vault based on a reference template."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class PruneError(Exception):
    """Raised when pruning fails."""


@dataclass
class PruneResult:
    removed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.removed)

    def summary(self) -> str:
        if not self.removed:
            return "No keys pruned."
        keys = ", ".join(self.removed)
        return f"Pruned {self.count} key(s): {keys}"


def prune_vault(
    vault_path: Path,
    identity_path: Path,
    keep_keys: Iterable[str],
    *,
    output_path: Path | None = None,
    recipients_path: Path | None = None,
) -> PruneResult:
    """Remove keys from *vault_path* that are not in *keep_keys*.

    Args:
        vault_path: Encrypted .env.age vault to prune.
        identity_path: age identity file for decryption.
        keep_keys: Iterable of key names that should be retained.
        output_path: Destination for the pruned vault (defaults to vault_path).
        recipients_path: Path to recipients file (defaults to vault sibling).

    Returns:
        PruneResult describing what was removed.
    """
    if not vault_path.exists():
        raise PruneError(f"Vault not found: {vault_path}")

    keep_set = set(keep_keys)

    plaintext = decrypt(vault_path, identity_path)
    env = parse_dotenv(plaintext)

    result = PruneResult()
    pruned: dict[str, str] = {}
    for key, value in env.items():
        if key in keep_set:
            pruned[key] = value
            result.kept.append(key)
        else:
            result.removed.append(key)

    if not result.removed:
        return result

    rpath = recipients_path or vault_path.parent / ".recipients"
    recipients = load_recipients(rpath)
    if not recipients:
        raise PruneError("No recipients found; cannot re-encrypt pruned vault.")

    new_plaintext = serialize_dotenv(pruned)
    dest = output_path or vault_path
    encrypt(new_plaintext, dest, recipients)
    return result
