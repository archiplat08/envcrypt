"""Redact sensitive values in a decrypted env mapping for safe display."""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, List, Optional

# Keys whose values are always fully redacted regardless of other rules
_SENSITIVE_PATTERNS: List[str] = [
    "*SECRET*",
    "*PASSWORD*",
    "*PASSWD*",
    "*TOKEN*",
    "*API_KEY*",
    "*PRIVATE_KEY*",
    "*CREDENTIALS*",
    "*AUTH*",
]

_REDACTED = "***"


class RedactError(Exception):
    """Raised when redaction cannot be performed."""


@dataclass
class RedactResult:
    redacted: Dict[str, str] = field(default_factory=dict)
    redacted_keys: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.redacted_keys)

    def summary(self) -> str:
        if not self.redacted_keys:
            return "No keys redacted."
        keys = ", ".join(sorted(self.redacted_keys))
        return f"{self.count} key(s) redacted: {keys}"


def _is_sensitive(key: str, extra_patterns: Optional[List[str]] = None) -> bool:
    upper = key.upper()
    patterns = _SENSITIVE_PATTERNS + (extra_patterns or [])
    return any(fnmatch(upper, p.upper()) for p in patterns)


def redact_env(
    env: Dict[str, str],
    *,
    extra_patterns: Optional[List[str]] = None,
    partial: bool = False,
) -> RedactResult:
    """Return a copy of *env* with sensitive values replaced.

    Args:
        env: Plain key/value mapping.
        extra_patterns: Additional glob patterns to treat as sensitive.
        partial: When True, show first and last character with *** in between
                 instead of full redaction (useful for debugging).
    """
    result: Dict[str, str] = {}
    redacted_keys: List[str] = []

    for key, value in env.items():
        if _is_sensitive(key, extra_patterns):
            if partial and len(value) >= 2:
                masked = f"{value[0]}***{value[-1]}"
            else:
                masked = _REDACTED
            result[key] = masked
            redacted_keys.append(key)
        else:
            result[key] = value

    return RedactResult(redacted=result, redacted_keys=redacted_keys)
