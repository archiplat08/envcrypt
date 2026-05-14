"""Mask sensitive values in a decrypted env dict for safe display."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv
from envcrypt.env_redact import _is_sensitive

_MASK = "********"
_PARTIAL_VISIBLE = 4  # chars to reveal at the start for partial mode


class MaskError(Exception):
    """Raised when masking fails."""


@dataclass
class MaskEntry:
    key: str
    original: str
    masked: str
    sensitive: bool

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.key}={self.masked}"


@dataclass
class MaskResult:
    entries: List[MaskEntry] = field(default_factory=list)

    @property
    def masked_count(self) -> int:
        return sum(1 for e in self.entries if e.sensitive)

    def as_dict(self) -> Dict[str, str]:
        return {e.key: e.masked for e in self.entries}

    def summary(self) -> str:
        total = len(self.entries)
        masked = self.masked_count
        return f"{masked}/{total} sensitive keys masked."


def _mask_value(value: str, partial: bool = False) -> str:
    """Return a masked representation of *value*."""
    if not value:
        return _MASK
    if partial and len(value) > _PARTIAL_VISIBLE:
        return value[:_PARTIAL_VISIBLE] + "*" * (len(value) - _PARTIAL_VISIBLE)
    return _MASK


def mask_env(
    env: Dict[str, str],
    extra_patterns: Optional[List[str]] = None,
    partial: bool = False,
) -> MaskResult:
    """Mask sensitive values in *env* dict.

    Args:
        env: Plain key/value mapping.
        extra_patterns: Additional glob patterns that mark a key as sensitive.
        partial: When True, reveal the first few characters of each value.

    Returns:
        :class:`MaskResult` with one entry per key.
    """
    entries: List[MaskEntry] = []
    for key, value in env.items():
        sensitive = _is_sensitive(key, extra_patterns or [])
        masked = _mask_value(value, partial=partial) if sensitive else value
        entries.append(MaskEntry(key=key, original=value, masked=masked, sensitive=sensitive))
    return MaskResult(entries=entries)


def mask_vault(
    vault_path: Path,
    identity_path: Path,
    extra_patterns: Optional[List[str]] = None,
    partial: bool = False,
) -> MaskResult:
    """Decrypt *vault_path* and return a :class:`MaskResult` with masked values.

    Raises:
        MaskError: If decryption fails.
    """
    try:
        plaintext = decrypt(vault_path, identity_path)
    except Exception as exc:
        raise MaskError(f"Failed to decrypt vault: {exc}") from exc
    env = parse_dotenv(plaintext)
    return mask_env(env, extra_patterns=extra_patterns, partial=partial)
