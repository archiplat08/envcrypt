"""Set or update individual keys in an encrypted vault."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class SetError(Exception):
    """Raised when a set/unset operation fails."""


@dataclass
class SetResult:
    vault: Path
    updated: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append(f"added: {', '.join(sorted(self.added))}")
        if self.updated:
            parts.append(f"updated: {', '.join(sorted(self.updated))}")
        return "; ".join(parts) if parts else "no changes"


def set_keys(
    vault: Path,
    pairs: Dict[str, str],
    identity: Path,
    recipients_file: Optional[Path] = None,
    output: Optional[Path] = None,
) -> SetResult:
    """Decrypt *vault*, apply *pairs*, re-encrypt and write to *output*."""
    if not vault.exists():
        raise SetError(f"Vault not found: {vault}")
    if not pairs:
        raise SetError("No key=value pairs provided.")

    recipients_path = recipients_file or vault.parent / ".recipients"
    recipients = load_recipients(recipients_path)
    if not recipients:
        raise SetError(f"No recipients found in {recipients_path}")

    plaintext = decrypt(vault, identity)
    env = parse_dotenv(plaintext)

    result = SetResult(vault=vault)
    for key, value in pairs.items():
        if key in env:
            result.updated.append(key)
        else:
            result.added.append(key)
        env[key] = value

    new_plaintext = serialize_dotenv(env)
    dest = output or vault
    encrypt(new_plaintext, recipients, dest)
    return result
