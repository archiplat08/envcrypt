"""Patch (set/unset) individual keys in an encrypted vault without full re-encryption."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class PatchError(Exception):
    """Raised when a patch operation fails."""


@dataclass
class PatchResult:
    set_keys: List[str] = field(default_factory=list)
    unset_keys: List[str] = field(default_factory=list)
    skipped_keys: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.set_keys:
            parts.append(f"set: {', '.join(self.set_keys)}")
        if self.unset_keys:
            parts.append(f"unset: {', '.join(self.unset_keys)}")
        if self.skipped_keys:
            parts.append(f"skipped (already absent): {', '.join(self.skipped_keys)}")
        return "; ".join(parts) if parts else "no changes"


def patch_vault(
    vault_path: Path,
    identity_path: Path,
    *,
    set_pairs: Optional[Dict[str, str]] = None,
    unset_keys: Optional[List[str]] = None,
    recipients_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> PatchResult:
    """Decrypt a vault, apply key-level patches, and re-encrypt in place.

    Args:
        vault_path: Path to the encrypted .env.age file.
        identity_path: Path to the age private key used for decryption.
        set_pairs: Keys to add or overwrite.
        unset_keys: Keys to remove from the env.
        recipients_path: Recipients file for re-encryption (defaults to .env.recipients next to vault).
        output_path: Where to write the patched vault (defaults to vault_path).

    Returns:
        A PatchResult describing what changed.
    """
    if not vault_path.exists():
        raise PatchError(f"Vault not found: {vault_path}")

    set_pairs = set_pairs or {}
    unset_keys = unset_keys or []

    recipients_file = recipients_path or vault_path.parent / ".env.recipients"
    recipients = load_recipients(recipients_file)
    if not recipients:
        raise PatchError(f"No recipients found in {recipients_file}")

    plaintext = decrypt(vault_path, identity_path)
    env = parse_dotenv(plaintext)

    result = PatchResult()

    for key, value in set_pairs.items():
        env[key] = value
        result.set_keys.append(key)

    for key in unset_keys:
        if key in env:
            del env[key]
            result.unset_keys.append(key)
        else:
            result.skipped_keys.append(key)

    new_plaintext = serialize_dotenv(env)
    dest = output_path or vault_path
    encrypt(new_plaintext, dest, recipients)

    return result
