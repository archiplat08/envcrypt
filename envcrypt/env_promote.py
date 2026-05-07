"""Promote (copy) a vault from one environment to another with optional key filtering."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class PromoteError(Exception):
    """Raised when a promotion operation fails."""


@dataclass
class PromoteResult:
    source: Path
    destination: Path
    promoted_keys: List[str] = field(default_factory=list)
    skipped_keys: List[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return (
            f"Promoted {len(self.promoted_keys)} key(s) from '{self.source}' "
            f"to '{self.destination}' ({len(self.skipped_keys)} skipped)."
        )


def promote_vault(
    source_vault: Path,
    dest_vault: Path,
    identity_file: Path,
    recipients_file: Optional[Path] = None,
    include_keys: Optional[List[str]] = None,
    exclude_keys: Optional[List[str]] = None,
    overwrite: bool = True,
) -> PromoteResult:
    """Decrypt *source_vault*, optionally filter keys, then re-encrypt into *dest_vault*.

    If *dest_vault* already exists its contents are merged; existing keys are kept
    unless *overwrite* is True.
    """
    if not source_vault.exists():
        raise PromoteError(f"Source vault not found: {source_vault}")

    recipients_path = recipients_file or source_vault.parent / ".recipients"
    recipients = load_recipients(recipients_path)
    if not recipients:
        raise PromoteError(f"No recipients found in '{recipients_path}'.")

    # Decrypt source
    try:
        source_plaintext = decrypt(source_vault, identity_file)
    except Exception as exc:  # pragma: no cover
        raise PromoteError(f"Failed to decrypt source vault: {exc}") from exc

    source_env = parse_dotenv(source_plaintext)

    # Determine which keys to promote
    promoted: dict[str, str] = {}
    skipped: list[str] = []
    for key, value in source_env.items():
        if include_keys and key not in include_keys:
            skipped.append(key)
            continue
        if exclude_keys and key in exclude_keys:
            skipped.append(key)
            continue
        promoted[key] = value

    # Merge with existing destination vault (if present)
    dest_env: dict[str, str] = {}
    if dest_vault.exists():
        try:
            dest_plaintext = decrypt(dest_vault, identity_file)
            dest_env = parse_dotenv(dest_plaintext)
        except Exception as exc:  # pragma: no cover
            raise PromoteError(f"Failed to decrypt destination vault: {exc}") from exc

    for key, value in promoted.items():
        if key in dest_env and not overwrite:
            skipped.append(key)
        else:
            dest_env[key] = value

    final_keys = [k for k in promoted if k not in skipped]

    merged_text = serialize_dotenv(dest_env)
    try:
        encrypt(merged_text, dest_vault, recipients)
    except Exception as exc:  # pragma: no cover
        raise PromoteError(f"Failed to encrypt destination vault: {exc}") from exc

    return PromoteResult(
        source=source_vault,
        destination=dest_vault,
        promoted_keys=final_keys,
        skipped_keys=skipped,
    )
