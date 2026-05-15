"""Squash multiple vault snapshots into a single clean vault."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class SquashError(Exception):
    """Raised when squashing fails."""


@dataclass
class SquashResult:
    source_files: List[Path]
    output: Path
    keys_merged: int
    keys_overwritten: int

    def summary(self) -> str:
        return (
            f"Squashed {len(self.source_files)} vault(s) into {self.output} "
            f"({self.keys_merged} keys, {self.keys_overwritten} overwritten)"
        )


def squash_vaults(
    sources: List[Path],
    identity: Path,
    output: Optional[Path] = None,
    recipients_file: Optional[Path] = None,
    last_wins: bool = True,
) -> SquashResult:
    """Merge multiple encrypted vault files into one, last-write-wins by default."""
    if not sources:
        raise SquashError("At least one source vault is required.")

    for src in sources:
        if not src.exists():
            raise SquashError(f"Source vault not found: {src}")

    ref = sources[0]
    recipients_path = recipients_file or ref.parent / ".envcrypt_recipients"
    recipients = load_recipients(recipients_path)
    if not recipients:
        raise SquashError("No recipients found; cannot re-encrypt squashed vault.")

    merged: dict[str, str] = {}
    overwritten = 0

    for src in sources:
        plaintext = decrypt(src, identity)
        pairs = parse_dotenv(plaintext)
        for k, v in pairs.items():
            if k in merged:
                if last_wins:
                    merged[k] = v
                    overwritten += 1
            else:
                merged[k] = v

    serialized = serialize_dotenv(merged)
    out_path = output or ref.with_suffix(".squashed.env.age")
    encrypt(serialized, out_path, recipients)

    return SquashResult(
        source_files=list(sources),
        output=out_path,
        keys_merged=len(merged),
        keys_overwritten=overwritten,
    )
