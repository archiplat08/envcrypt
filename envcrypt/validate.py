"""Validate decrypted .env files against a required-keys schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from envcrypt.dotenv import parse_dotenv, read_dotenv_file


@dataclass
class ValidationIssue:
    key: str
    message: str

    def __str__(self) -> str:
        return f"{self.key}: {self.message}"


@dataclass
class ValidationResult:
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.issues) == 0

    def __str__(self) -> str:
        if self.ok:
            return "All required keys present and non-empty."
        lines = ["Validation failed:"]
        for issue in self.issues:
            lines.append(f"  - {issue}")
        return "\n".join(lines)


def load_schema(schema_path: Path) -> list[str]:
    """Load required keys from a plain-text schema file (one key per line)."""
    lines = schema_path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def validate_env(
    env: dict[str, str],
    required_keys: Iterable[str],
    *,
    allow_empty: bool = False,
) -> ValidationResult:
    """Check that every required key exists in *env* and is non-empty."""
    result = ValidationResult()
    for key in required_keys:
        if key not in env:
            result.issues.append(ValidationIssue(key, "missing"))
        elif not allow_empty and not env[key].strip():
            result.issues.append(ValidationIssue(key, "present but empty"))
    return result


def validate_env_file(
    env_path: Path,
    schema_path: Path,
    *,
    allow_empty: bool = False,
) -> ValidationResult:
    """Parse *env_path* and validate it against the schema at *schema_path*."""
    raw = read_dotenv_file(env_path)
    env = parse_dotenv(raw)
    required_keys = load_schema(schema_path)
    return validate_env(env, required_keys, allow_empty=allow_empty)
