"""Rename or alias keys inside an encrypted vault."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class RenameError(Exception):
    """Raised when a rename operation fails."""


@dataclass
class RenameResult:
    old_key: str
    new_key: str
    vault: Path
    aliased: bool  # True if old key was kept as alias


def rename_key(
    vault: Path,
    identity: Path,
    old_key: str,
    new_key: str,
    *,
    keep_alias: bool = False,
    recipients_file: Optional[Path] = None,
) -> RenameResult:
    """Rename *old_key* to *new_key* inside *vault*.

    If *keep_alias* is True the old key is retained with the same value
    so existing consumers continue to work.
    """
    if not vault.exists():
        raise RenameError(f"Vault not found: {vault}")

    recipients = load_recipients(recipients_file or vault.parent / ".recipients")
    if not recipients:
        raise RenameError("No recipients found — cannot re-encrypt vault.")

    plaintext = decrypt(vault, identity)
    env = parse_dotenv(plaintext)

    if old_key not in env:
        raise RenameError(f"Key '{old_key}' not found in vault.")
    if new_key in env and new_key != old_key:
        raise RenameError(
            f"Key '{new_key}' already exists in vault. Remove it first."
        )

    value = env[old_key]
    if not keep_alias:
        del env[old_key]
    env[new_key] = value

    # Preserve insertion order: new key takes old key's position when not aliasing
    if not keep_alias:
        ordered: dict[str, str] = {}
        for k, v in list(env.items()):
            if k == new_key:
                ordered[new_key] = value
            else:
                ordered[k] = v
        env = ordered

    new_plaintext = serialize_dotenv(env)
    encrypt(new_plaintext.encode(), vault, recipients)

    return RenameResult(
        old_key=old_key,
        new_key=new_key,
        vault=vault,
        aliased=keep_alias,
    )
