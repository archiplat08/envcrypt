"""Import env variables from external sources into a vault."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from envcrypt.dotenv import parse_dotenv
from envcrypt.vault import encrypt_env_file


class ImportError(Exception):  # noqa: A001
    """Raised when an import operation fails."""


def import_from_dotenv(source: Path, recipients_file: Path, output: Optional[Path] = None) -> Path:
    """Import a plain .env file and encrypt it into a vault.

    Args:
        source: Path to the plain .env file to import.
        recipients_file: Path to the recipients file for encryption.
        output: Optional output path for the vault file.

    Returns:
        Path to the created vault file.
    """
    if not source.exists():
        raise ImportError(f"Source file not found: {source}")

    output = output or source.with_suffix(".env.age")
    encrypt_env_file(source, recipients_file, output)
    return output


def import_from_json(source: Path, recipients_file: Path, output: Optional[Path] = None) -> Path:
    """Import a JSON file of key/value pairs and encrypt it into a vault.

    Args:
        source: Path to the JSON file (flat key/value object).
        recipients_file: Path to the recipients file for encryption.
        output: Optional output path for the vault file.

    Returns:
        Path to the created vault file.
    """
    if not source.exists():
        raise ImportError(f"Source file not found: {source}")

    try:
        data: Dict[str, str] = json.loads(source.read_text())
    except json.JSONDecodeError as exc:
        raise ImportError(f"Invalid JSON in {source}: {exc}") from exc

    if not isinstance(data, dict):
        raise ImportError("JSON source must be a flat key/value object.")

    non_string = [k for k, v in data.items() if not isinstance(v, (str, int, float, bool))]
    if non_string:
        raise ImportError(f"Nested values are not supported. Offending keys: {non_string}")

    env_lines = [f"{k}={v}" for k, v in data.items()]
    env_content = "\n".join(env_lines) + "\n"

    tmp_path = source.with_suffix(".tmp.env")
    try:
        tmp_path.write_text(env_content)
        output = output or source.with_suffix(".env.age")
        encrypt_env_file(tmp_path, recipients_file, output)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return output


def import_from_shell_env(keys: list[str], recipients_file: Path, output: Path) -> Path:
    """Import specific keys from the current shell environment into a vault.

    Args:
        keys: List of environment variable names to capture.
        recipients_file: Path to the recipients file for encryption.
        output: Output path for the vault file.

    Returns:
        Path to the created vault file.
    """
    missing = [k for k in keys if k not in os.environ]
    if missing:
        raise ImportError(f"Keys not found in environment: {missing}")

    env_lines = [f"{k}={os.environ[k]}" for k in keys]
    env_content = "\n".join(env_lines) + "\n"

    tmp_path = output.with_suffix(".tmp.env")
    try:
        tmp_path.write_text(env_content)
        encrypt_env_file(tmp_path, recipients_file, output)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return output
