"""Lint .env files for common issues and best practices."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from envcrypt.dotenv import read_dotenv_file


@dataclass
class LintIssue:
    line: int
    key: str
    severity: str  # "error" | "warning" | "info"
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] line {self.line}: {self.key} — {self.message}"


@dataclass
class LintResult:
    path: Path
    issues: List[LintIssue] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(i.severity == "error" for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == "warning" for i in self.issues)


_SENSITIVE_PATTERNS = ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY", "PRIVATE")
_PLACEHOLDER_VALUES = ("", "changeme", "todo", "fixme", "your_secret_here", "<secret>")


def lint_env_file(path: Path) -> LintResult:
    """Lint a .env file and return a LintResult with any issues found."""
    result = LintResult(path=path)
    raw_lines = path.read_text().splitlines()
    pairs = read_dotenv_file(path)

    seen_keys: dict[str, int] = {}

    for lineno, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        # Duplicate key check
        if key in seen_keys:
            result.issues.append(LintIssue(
                line=lineno, key=key, severity="warning",
                message=f"duplicate key (first seen on line {seen_keys[key]})"
            ))
        else:
            seen_keys[key] = lineno

        # Placeholder value check for sensitive keys
        upper_key = key.upper()
        if any(pat in upper_key for pat in _SENSITIVE_PATTERNS):
            if value.lower() in _PLACEHOLDER_VALUES:
                result.issues.append(LintIssue(
                    line=lineno, key=key, severity="error",
                    message="sensitive key appears to have a placeholder or empty value"
                ))

        # Whitespace in key
        if " " in key or "\t" in key:
            result.issues.append(LintIssue(
                line=lineno, key=key, severity="error",
                message="key contains whitespace"
            ))

        # Key not uppercase
        if key != key.upper():
            result.issues.append(LintIssue(
                line=lineno, key=key, severity="warning",
                message="key is not uppercase"
            ))

    return result
