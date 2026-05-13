"""Checksum utilities for vault files — track and verify content integrity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional


class ChecksumError(Exception):
    """Raised when a checksum operation fails."""


def _checksum_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".checksum.json")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def compute_checksum(vault_path: Path) -> str:
    """Return the SHA-256 hex digest of *vault_path*."""
    if not vault_path.exists():
        raise ChecksumError(f"Vault not found: {vault_path}")
    return _sha256(vault_path)


def save_checksum(vault_path: Path) -> str:
    """Compute and persist the checksum for *vault_path*. Returns the digest."""
    digest = compute_checksum(vault_path)
    record = {"vault": vault_path.name, "sha256": digest}
    _checksum_path(vault_path).write_text(json.dumps(record, indent=2))
    return digest


def load_checksum(vault_path: Path) -> Optional[str]:
    """Load a previously saved checksum. Returns *None* if no checksum file exists."""
    cp = _checksum_path(vault_path)
    if not cp.exists():
        return None
    try:
        data = json.loads(cp.read_text())
        return data["sha256"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise ChecksumError(f"Corrupt checksum file: {cp}") from exc


def verify_checksum(vault_path: Path) -> bool:
    """Verify *vault_path* against its saved checksum.

    Returns *True* if they match, *False* if they differ.
    Raises :class:`ChecksumError` when no checksum has been saved yet.
    """
    saved = load_checksum(vault_path)
    if saved is None:
        raise ChecksumError(
            f"No checksum on record for {vault_path}. Run 'save_checksum' first."
        )
    current = compute_checksum(vault_path)
    return current == saved
