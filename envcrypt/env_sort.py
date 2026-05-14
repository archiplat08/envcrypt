"""Sort keys in a vault by name, prefix, or custom order."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class SortError(Exception):
    """Raised when sorting fails."""


@dataclass
class SortResult:
    original_order: List[str]
    sorted_order: List[str]
    changed: bool

    def summary(self) -> str:
        if not self.changed:
            return "Keys already in sorted order — no changes made."
        return (
            f"Sorted {len(self.sorted_order)} key(s): "
            + ", ".join(self.sorted_order[:5])
            + (" …" if len(self.sorted_order) > 5 else "")
        )


def sort_vault(
    vault: Path,
    identity: Path,
    *,
    reverse: bool = False,
    group_by_prefix: bool = False,
    output: Optional[Path] = None,
    recipients_file: Optional[Path] = None,
) -> SortResult:
    """Decrypt *vault*, sort its keys, re-encrypt and write to *output*.

    Parameters
    ----------
    vault:            Path to the encrypted vault file.
    identity:         Path to the age private key used for decryption.
    reverse:          If True, sort in descending order.
    group_by_prefix:  If True, group keys sharing the same ``PREFIX_`` together
                      before sorting within each group.
    output:           Destination path; defaults to overwriting *vault*.
    recipients_file:  Path to the recipients file; defaults to sibling
                      ``recipients.txt``.
    """
    if not vault.exists():
        raise SortError(f"Vault not found: {vault}")

    recipients_path = recipients_file or vault.parent / "recipients.txt"
    recipients = load_recipients(recipients_path)
    if not recipients:
        raise SortError("No recipients found — cannot re-encrypt sorted vault.")

    plaintext = decrypt(vault, identity)
    env = parse_dotenv(plaintext)

    original_order = list(env.keys())

    if group_by_prefix:
        def _sort_key(k: str) -> tuple:
            parts = k.split("_", 1)
            prefix = parts[0] if len(parts) > 1 else ""
            return (prefix, k)
        sorted_keys = sorted(env.keys(), key=_sort_key, reverse=reverse)
    else:
        sorted_keys = sorted(env.keys(), reverse=reverse)

    sorted_env = {k: env[k] for k in sorted_keys}
    changed = original_order != sorted_keys

    if changed:
        dest = output or vault
        new_plaintext = serialize_dotenv(sorted_env)
        encrypt(new_plaintext, dest, recipients)

    return SortResult(
        original_order=original_order,
        sorted_order=sorted_keys,
        changed=changed,
    )
