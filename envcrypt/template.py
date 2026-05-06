"""Template generation for .env files — produce a sanitized .env.example from a vault."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from envcrypt.dotenv import parse_dotenv, serialize_dotenv, read_dotenv_file
from envcrypt.vault import decrypt_env_file


SENSITIVE_PATTERN = re.compile(
    r"(secret|password|passwd|token|key|api|auth|private|cert|credential)",
    re.IGNORECASE,
)


class TemplateError(Exception):
    """Raised when template generation fails."""


def _placeholder_for(key: str, value: str) -> str:
    """Return a placeholder string appropriate for the key/value pair."""
    if SENSITIVE_PATTERN.search(key):
        return f"<your_{key.lower()}>"
    if value.isdigit():
        return "0"
    if value.lower() in ("true", "false"):
        return value.lower()
    return f"<{key.lower()}>"


def generate_template(
    env: dict[str, str],
    *,
    keep_values: bool = False,
    comment_header: Optional[str] = None,
) -> str:
    """Generate a .env.example template from a parsed env dict.

    Args:
        env: Mapping of key -> value.
        keep_values: If True, preserve original values instead of placeholders.
        comment_header: Optional comment block prepended to the output.

    Returns:
        String contents suitable for writing to a .env.example file.
    """
    lines: list[str] = []

    if comment_header:
        for line in comment_header.splitlines():
            lines.append(f"# {line}" if not line.startswith("#") else line)
        lines.append("")

    template_env = {
        key: (value if keep_values else _placeholder_for(key, value))
        for key, value in env.items()
    }
    lines.append(serialize_dotenv(template_env))
    return "\n".join(lines)


def generate_template_from_vault(
    vault_path: str | Path,
    identity_path: str | Path,
    output_path: Optional[str | Path] = None,
    *,
    keep_values: bool = False,
    comment_header: Optional[str] = None,
) -> Path:
    """Decrypt a vault and write a .env.example template.

    Args:
        vault_path: Path to the encrypted .env.age file.
        identity_path: Path to the age private key file.
        output_path: Destination path; defaults to <vault_path>.example.
        keep_values: If True, preserve plaintext values in the template.
        comment_header: Optional comment block prepended to the output.

    Returns:
        Path to the written template file.
    """
    vault_path = Path(vault_path)
    if output_path is None:
        stem = vault_path.stem  # e.g. ".env" from ".env.age"
        output_path = vault_path.parent / f"{stem}.example"
    output_path = Path(output_path)

    try:
        plaintext_path = decrypt_env_file(str(vault_path), str(identity_path))
    except Exception as exc:
        raise TemplateError(f"Failed to decrypt vault: {exc}") from exc

    try:
        env = read_dotenv_file(str(plaintext_path))
    finally:
        plaintext_path.unlink(missing_ok=True)

    content = generate_template(env, keep_values=keep_values, comment_header=comment_header)
    output_path.write_text(content)
    return output_path
