"""Clone a vault to a new file, optionally filtering keys."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class CloneError(Exception):
    """Raised when cloning fails."""


@dataclass
class CloneResult:
    source: Path
    destination: Path
    keys_copied: list[str] = field(default_factory=list)
    keys_skipped: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Cloned {len(self.keys_copied)} key(s) from '{self.source}' "
            f"to '{self.destination}' "
            f"({len(self.keys_skipped)} skipped)."
        )


def clone_vault(
    source: Path,
    destination: Path,
    identity: Path,
    *,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    recipients_file: Path | None = None,
) -> CloneResult:
    """Decrypt *source*, optionally filter keys, re-encrypt to *destination*.

    If *include* is given only those keys are kept.
    If *exclude* is given those keys are dropped.
    Both cannot be supplied simultaneously.
    """
    if include is not None and exclude is not None:
        raise CloneError("Specify either 'include' or 'exclude', not both.")

    if not source.exists():
        raise CloneError(f"Source vault not found: {source}")

    include_set = set(include) if include is not None else None
    exclude_set = set(exclude) if exclude is not None else set()

    try:
        plaintext = decrypt(source, identity)
    except Exception as exc:
        raise CloneError(f"Failed to decrypt source vault: {exc}") from exc

    env = parse_dotenv(plaintext)

    copied: list[str] = []
    skipped: list[str] = []
    filtered: dict[str, str] = {}

    for key, value in env.items():
        if include_set is not None and key not in include_set:
            skipped.append(key)
            continue
        if key in exclude_set:
            skipped.append(key)
            continue
        filtered[key] = value
        copied.append(key)

    rfile = recipients_file or source.parent / ".recipients"
    recipients = load_recipients(rfile)
    if not recipients:
        raise CloneError("No recipients found; cannot encrypt cloned vault.")

    new_plaintext = serialize_dotenv(filtered)
    try:
        encrypt(new_plaintext, destination, recipients)
    except Exception as exc:
        raise CloneError(f"Failed to encrypt cloned vault: {exc}") from exc

    return CloneResult(
        source=source,
        destination=destination,
        keys_copied=copied,
        keys_skipped=skipped,
    )
