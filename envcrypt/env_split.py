"""Split a vault into multiple smaller vaults by prefix or group."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class SplitError(Exception):
    """Raised when a vault split operation fails."""


@dataclass
class SplitResult:
    outputs: Dict[str, Path] = field(default_factory=dict)  # label -> path
    key_counts: Dict[str, int] = field(default_factory=dict)
    leftover_count: int = 0

    def summary(self) -> str:
        parts = [f"{label}={self.key_counts.get(label, 0)} keys" for label in self.outputs]
        if self.leftover_count:
            parts.append(f"leftover={self.leftover_count} keys")
        return ", ".join(parts) if parts else "no keys split"


def split_vault(
    vault: Path,
    identity: Path,
    prefixes: List[str],
    output_dir: Optional[Path] = None,
    recipients_file: Optional[Path] = None,
    keep_leftover: bool = True,
) -> SplitResult:
    """Split *vault* into one sub-vault per prefix.

    Keys whose names start with a given prefix (case-insensitive) are written
    to ``<output_dir>/<prefix>.env.age``.  Keys that don't match any prefix
    are written to ``<output_dir>/leftover.env.age`` when *keep_leftover* is
    True.
    """
    if not vault.exists():
        raise SplitError(f"Vault not found: {vault}")
    if not identity.exists():
        raise SplitError(f"Identity file not found: {identity}")

    out_dir = output_dir or vault.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    rec_file = recipients_file or vault.parent / ".recipients"
    recipients = load_recipients(rec_file)
    if not recipients:
        raise SplitError("No recipients found; cannot re-encrypt split vaults.")

    plaintext = decrypt(vault, identity)
    env = parse_dotenv(plaintext)

    buckets: Dict[str, Dict[str, str]] = {p.upper(): {} for p in prefixes}
    leftover: Dict[str, str] = {}

    for key, value in env.items():
        matched = False
        for prefix in prefixes:
            if key.upper().startswith(prefix.upper()):
                buckets[prefix.upper()][key] = value
                matched = True
                break
        if not matched:
            leftover[key] = value

    result = SplitResult()
    for prefix, keys in buckets.items():
        if not keys:
            continue
        out_path = out_dir / f"{prefix.lower()}.env.age"
        encrypt(serialize_dotenv(keys).encode(), recipients, out_path)
        result.outputs[prefix] = out_path
        result.key_counts[prefix] = len(keys)

    if keep_leftover and leftover:
        lo_path = out_dir / "leftover.env.age"
        encrypt(serialize_dotenv(leftover).encode(), recipients, lo_path)
        result.outputs["leftover"] = lo_path
        result.key_counts["leftover"] = len(leftover)
        result.leftover_count = len(leftover)

    return result
