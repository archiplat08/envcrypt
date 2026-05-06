"""Utilities for sharing encrypted .env files with specific recipients."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class ShareError(Exception):
    """Raised when a share operation fails."""


def share_vault(
    vault_path: Path,
    identity_file: Path,
    recipients: List[str],
    output_path: Optional[Path] = None,
    keys_file: Optional[Path] = None,
) -> Path:
    """Decrypt *vault_path* with *identity_file* and re-encrypt for *recipients*.

    If *recipients* is empty and *keys_file* is provided the recipients are
    loaded from that file.  The re-encrypted vault is written to *output_path*
    (defaults to ``<vault_stem>.shared<vault_suffix>``).

    Returns the path of the newly created shared vault.
    """
    if not recipients:
        if keys_file is None:
            raise ShareError("No recipients provided and no keys_file specified.")
        recipients = load_recipients(keys_file)

    if not recipients:
        raise ShareError("Recipient list is empty; cannot share vault.")

    vault_path = Path(vault_path)
    if not vault_path.exists():
        raise ShareError(f"Vault file not found: {vault_path}")

    # Decrypt to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".env") as tmp:
        tmp_path = Path(tmp.name)

    try:
        plaintext = decrypt(vault_path, identity_file)
        tmp_path.write_bytes(plaintext)

        # Validate the decrypted content is parseable
        parse_dotenv(plaintext.decode())

        if output_path is None:
            output_path = vault_path.with_name(
                vault_path.stem + ".shared" + vault_path.suffix
            )

        encrypt(tmp_path, recipients, output_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    return Path(output_path)


def share_subset(
    vault_path: Path,
    identity_file: Path,
    keys: List[str],
    recipients: List[str],
    output_path: Optional[Path] = None,
) -> Path:
    """Share only a *subset* of env keys from *vault_path* with *recipients*."""
    if not recipients:
        raise ShareError("Recipient list is empty; cannot share vault.")
    if not keys:
        raise ShareError("Key subset list is empty; nothing to share.")

    vault_path = Path(vault_path)
    plaintext = decrypt(vault_path, identity_file)
    env = parse_dotenv(plaintext.decode())

    subset = {k: env[k] for k in keys if k in env}
    missing = [k for k in keys if k not in env]
    if missing:
        raise ShareError(f"Keys not found in vault: {missing}")

    subset_text = serialize_dotenv(subset)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".env") as tmp:
        tmp_path = Path(tmp.name)

    try:
        tmp_path.write_text(subset_text)
        if output_path is None:
            output_path = vault_path.with_name(
                vault_path.stem + ".subset" + vault_path.suffix
            )
        encrypt(tmp_path, recipients, output_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    return Path(output_path)
