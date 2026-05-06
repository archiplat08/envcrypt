"""Sign and verify .env vault files using age identity checksums."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class SignError(Exception):
    """Raised when signing or verification fails."""


@dataclass
class SignatureInfo:
    vault: str
    sha256: str
    signer: Optional[str]
    timestamp: str


def _sig_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".sig.json")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def sign_vault(
    vault_path: Path,
    signer: Optional[str] = None,
) -> SignatureInfo:
    """Compute SHA-256 of vault and write a .sig.json alongside it."""
    vault_path = Path(vault_path)
    if not vault_path.exists():
        raise SignError(f"Vault not found: {vault_path}")

    from envcrypt.audit import _now_iso

    digest = _sha256_file(vault_path)
    timestamp = _now_iso()
    info = SignatureInfo(
        vault=vault_path.name,
        sha256=digest,
        signer=signer,
        timestamp=timestamp,
    )
    sig_path = _sig_path(vault_path)
    sig_path.write_text(
        json.dumps(
            {
                "vault": info.vault,
                "sha256": info.sha256,
                "signer": info.signer,
                "timestamp": info.timestamp,
            },
            indent=2,
        )
    )
    return info


def verify_vault(vault_path: Path) -> SignatureInfo:
    """Verify vault integrity against its .sig.json file."""
    vault_path = Path(vault_path)
    if not vault_path.exists():
        raise SignError(f"Vault not found: {vault_path}")

    sig_path = _sig_path(vault_path)
    if not sig_path.exists():
        raise SignError(f"No signature file found for {vault_path.name}")

    try:
        data = json.loads(sig_path.read_text())
    except json.JSONDecodeError as exc:
        raise SignError(f"Corrupt signature file: {exc}") from exc

    expected = data.get("sha256", "")
    actual = _sha256_file(vault_path)
    if actual != expected:
        raise SignError(
            f"Signature mismatch for {vault_path.name}: "
            f"expected {expected}, got {actual}"
        )

    return SignatureInfo(
        vault=data.get("vault", vault_path.name),
        sha256=actual,
        signer=data.get("signer"),
        timestamp=data.get("timestamp", ""),
    )
