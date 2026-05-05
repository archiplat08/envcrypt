"""Utilities for reading and writing .env files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional


class DotEnvError(Exception):
    """Raised when a .env file cannot be parsed or written."""


_LINE_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)\s*$"
)


def parse_dotenv(text: str) -> Dict[str, str]:
    """Parse the contents of a .env file into a key/value dict.

    Lines starting with '#' and blank lines are ignored.
    Values may optionally be quoted with single or double quotes.
    """
    result: Dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _LINE_RE.match(line)
        if not match:
            raise DotEnvError(f"Invalid syntax on line {lineno}: {line!r}")
        key = match.group("key")
        value = match.group("value").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key] = value
    return result


def serialize_dotenv(env: Dict[str, str]) -> str:
    """Serialize a key/value dict to .env file contents."""
    lines = []
    for key, value in env.items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise DotEnvError(f"Invalid environment variable name: {key!r}")
        if " " in value or "#" in value or not value:
            value = f'"{value}"'
        lines.append(f"{key}={value}")
    return "\n".join(lines) + ("\n" if lines else "")


def read_dotenv_file(path: Path) -> Dict[str, str]:
    """Read and parse a .env file from *path*."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DotEnvError(f"Cannot read file {path}: {exc}") from exc
    return parse_dotenv(text)


def write_dotenv_file(path: Path, env: Dict[str, str]) -> None:
    """Serialize *env* and write it to *path*."""
    text = serialize_dotenv(env)
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise DotEnvError(f"Cannot write file {path}: {exc}") from exc
