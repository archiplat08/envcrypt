"""Secret detection: flag keys whose values look like real secrets."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.dotenv import read_dotenv_file

# Patterns that suggest a value is a real secret (not a placeholder)
_SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$"),          # base64-ish long string
    re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE),        # hex token
    re.compile(r"^(sk|pk|rk|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}"),  # known prefixes
    re.compile(r"^ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"-----BEGIN .+?-----"),                    # PEM block
]

_SENSITIVE_KEY = re.compile(
    r"(password|passwd|secret|token|key|api_key|auth|credential|private)",
    re.IGNORECASE,
)


class SecretError(Exception):
    pass


@dataclass
class SecretFinding:
    key: str
    reason: str

    def __str__(self) -> str:
        return f"{self.key}: {self.reason}"


@dataclass
class SecretScanResult:
    findings: List[SecretFinding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0

    def summary(self) -> str:
        if self.clean:
            return "No secrets detected."
        return f"{len(self.findings)} potential secret(s) detected."


def _looks_like_secret(value: str) -> Optional[str]:
    """Return a reason string if the value looks like a real secret, else None."""
    if not value or value.startswith("<") and value.endswith(">"):
        return None
    for pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            return f"value matches secret pattern '{pattern.pattern[:30]}'"
    return None


def scan_env(env: Dict[str, str]) -> SecretScanResult:
    """Scan an env dict for values that look like real secrets."""
    result = SecretScanResult()
    for key, value in env.items():
        reason = _looks_like_secret(value)
        if reason and _SENSITIVE_KEY.search(key):
            result.findings.append(SecretFinding(key=key, reason=reason))
    return result


def scan_env_file(path: Path) -> SecretScanResult:
    """Parse a .env file and scan it for exposed secrets."""
    if not path.exists():
        raise SecretError(f"File not found: {path}")
    env = read_dotenv_file(path)
    return scan_env(env)
