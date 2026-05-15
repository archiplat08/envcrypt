"""Reorder keys in a vault according to a specified key ordering list."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class ReorderError(Exception):
    """Raised when reordering fails."""


@dataclass
class ReorderResult:
    vault: Path
    moved: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.moved:
            return "No keys were reordered."
        return (
            f"Reordered {len(self.moved)} key(s): {', '.join(self.moved)}. "
            f"{len(self.unchanged)} key(s) unchanged."
        )


def reorder_vault(
    vault: Path,
    order: List[str],
    identity: Path,
    output: Optional[Path] = None,
    recipients_file: Optional[Path] = None,
) -> ReorderResult:
    """Reorder keys in *vault* so that keys listed in *order* appear first.

    Keys not mentioned in *order* are appended afterwards in their original
    relative order.  The re-encrypted vault is written to *output* (defaults
    to *vault*).
    """
    if not vault.exists():
        raise ReorderError(f"Vault not found: {vault}")

    plaintext = decrypt(vault, identity)
    env: Dict[str, str] = parse_dotenv(plaintext)

    known = [k for k in order if k in env]
    rest = [k for k in env if k not in set(order)]
    new_order = known + rest

    moved = [k for i, k in enumerate(new_order) if k != list(env.keys())[i] if i < len(env)]
    # Simpler: any key whose position changed
    original_positions = {k: i for i, k in enumerate(env.keys())}
    moved = [k for i, k in enumerate(new_order) if original_positions[k] != i]
    unchanged = [k for k in new_order if k not in moved]

    reordered: Dict[str, str] = {k: env[k] for k in new_order}

    rec_file = recipients_file or vault.parent / ".recipients"
    recipients = load_recipients(rec_file)
    if not recipients:
        raise ReorderError("No recipients found; cannot re-encrypt vault.")

    out_path = output or vault
    encrypt(serialize_dotenv(reordered), recipients, out_path)

    return ReorderResult(vault=out_path, moved=moved, unchanged=unchanged)
