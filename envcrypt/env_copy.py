"""Copy keys between vault files with optional key filtering."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class CopyError(Exception):
    """Raised when a vault copy operation fails."""


@dataclass
class CopyResult:
    copied: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return (
            f"Copied {len(self.copied)} key(s), skipped {len(self.skipped)} key(s)."
        )


def copy_keys(
    src_vault: Path,
    dst_vault: Path,
    identity_file: Path,
    keys: Optional[List[str]] = None,
    overwrite: bool = False,
    recipients_file: Optional[Path] = None,
) -> CopyResult:
    """Copy keys from *src_vault* into *dst_vault*.

    Args:
        src_vault: Encrypted source vault path.
        dst_vault: Encrypted destination vault path.
        identity_file: Age identity (private key) file for decryption.
        keys: Optional list of key names to copy; copies all if None.
        overwrite: If False, skip keys that already exist in destination.
        recipients_file: Recipients file for re-encryption; defaults to
            a ``.recipients`` file next to *dst_vault*.

    Returns:
        A :class:`CopyResult` describing what was copied or skipped.
    """
    if not src_vault.exists():
        raise CopyError(f"Source vault not found: {src_vault}")
    if not dst_vault.exists():
        raise CopyError(f"Destination vault not found: {dst_vault}")

    recipients_path = recipients_file or dst_vault.with_suffix(".recipients")
    recipients = load_recipients(recipients_path)
    if not recipients:
        raise CopyError(f"No recipients found in {recipients_path}")

    src_plain = decrypt(src_vault, identity_file)
    src_env = parse_dotenv(src_plain)

    dst_plain = decrypt(dst_vault, identity_file)
    dst_env = parse_dotenv(dst_plain)

    result = CopyResult()
    candidates = {k: v for k, v in src_env.items() if keys is None or k in keys}

    for key, value in candidates.items():
        if key in dst_env and not overwrite:
            result.skipped.append(key)
            continue
        dst_env[key] = value
        result.copied.append(key)

    merged_plain = serialize_dotenv(dst_env)
    encrypt(merged_plain, dst_vault, recipients)
    return result
