"""Sanitize vault env values by stripping dangerous characters or patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients


class SanitizeError(Exception):
    """Raised when sanitization fails."""


# Patterns considered dangerous in env values
_DANGEROUS_PATTERNS: List[re.Pattern] = [
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),  # control chars
    re.compile(r"\$\("),   # command substitution $(...)
    re.compile(r"`"),       # backtick execution
]


@dataclass
class SanitizeResult:
    sanitized: Dict[str, str]
    changed_keys: List[str] = field(default_factory=list)
    skipped_keys: List[str] = field(default_factory=list)

    def count(self) -> int:
        return len(self.changed_keys)

    def summary(self) -> str:
        return (
            f"{self.count()} key(s) sanitized, "
            f"{len(self.skipped_keys)} skipped"
        )


def _sanitize_value(value: str) -> str:
    """Strip dangerous patterns from a single value."""
    result = value
    for pattern in _DANGEROUS_PATTERNS:
        result = pattern.sub("", result)
    return result


def sanitize_env(env: Dict[str, str], skip_keys: Optional[List[str]] = None) -> SanitizeResult:
    """Sanitize all values in an env dict."""
    skip = set(skip_keys or [])
    sanitized: Dict[str, str] = {}
    changed: List[str] = []
    skipped: List[str] = []

    for key, value in env.items():
        if key in skip:
            sanitized[key] = value
            skipped.append(key)
            continue
        clean = _sanitize_value(value)
        sanitized[key] = clean
        if clean != value:
            changed.append(key)

    return SanitizeResult(sanitized=sanitized, changed_keys=changed, skipped_keys=skipped)


def sanitize_vault(
    vault_path: Path,
    identity_path: Path,
    output_path: Optional[Path] = None,
    skip_keys: Optional[List[str]] = None,
) -> SanitizeResult:
    """Decrypt vault, sanitize values, re-encrypt in place or to output_path."""
    if not vault_path.exists():
        raise SanitizeError(f"Vault not found: {vault_path}")

    recipients = load_recipients(vault_path)
    if not recipients:
        raise SanitizeError("No recipients configured for vault.")

    plaintext = decrypt(vault_path, identity_path)
    env = parse_dotenv(plaintext)
    result = sanitize_env(env, skip_keys=skip_keys)

    serialized = serialize_dotenv(result.sanitized)
    dest = output_path or vault_path
    encrypt(serialized, dest, recipients)
    return result
