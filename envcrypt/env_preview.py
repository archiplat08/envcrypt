"""Preview decrypted vault contents with optional masking of sensitive values."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv
from envcrypt.env_redact import _is_sensitive


class PreviewError(Exception):
    """Raised when vault preview fails."""


@dataclass
class PreviewEntry:
    key: str
    value: str
    masked: bool

    def __str__(self) -> str:
        display = "****" if self.masked else self.value
        return f"{self.key}={display}"


@dataclass
class PreviewResult:
    entries: List[PreviewEntry] = field(default_factory=list)
    vault: str = ""

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def masked_count(self) -> int:
        return sum(1 for e in self.entries if e.masked)

    def as_dict(self) -> Dict[str, str]:
        return {e.key: ("****" if e.masked else e.value) for e in self.entries}

    def summary(self) -> str:
        return (
            f"{self.total} key(s) previewed from '{self.vault}' "
            f"({self.masked_count} masked)."
        )


def preview_vault(
    vault_path: Path,
    identity_path: Path,
    mask_sensitive: bool = True,
    keys: Optional[List[str]] = None,
    extra_sensitive_patterns: Optional[List[str]] = None,
) -> PreviewResult:
    """Decrypt a vault and return a PreviewResult with optional masking.

    Args:
        vault_path: Path to the encrypted .env.age file.
        identity_path: Path to the age private key file.
        mask_sensitive: If True, values for sensitive keys are replaced with '****'.
        keys: Optional list of specific keys to include; None means all keys.
        extra_sensitive_patterns: Additional glob patterns treated as sensitive.

    Returns:
        PreviewResult containing PreviewEntry objects.

    Raises:
        PreviewError: If decryption or parsing fails.
    """
    if not vault_path.exists():
        raise PreviewError(f"Vault file not found: {vault_path}")
    if not identity_path.exists():
        raise PreviewError(f"Identity file not found: {identity_path}")

    try:
        plaintext = decrypt(str(vault_path), str(identity_path))
    except Exception as exc:
        raise PreviewError(f"Decryption failed: {exc}") from exc

    try:
        env = parse_dotenv(plaintext)
    except Exception as exc:
        raise PreviewError(f"Failed to parse decrypted content: {exc}") from exc

    entries: List[PreviewEntry] = []
    for key, value in env.items():
        if keys is not None and key not in keys:
            continue
        sensitive = mask_sensitive and _is_sensitive(
            key, extra_patterns=extra_sensitive_patterns or []
        )
        entries.append(PreviewEntry(key=key, value=value, masked=sensitive))

    return PreviewResult(entries=entries, vault=str(vault_path))
