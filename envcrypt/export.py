"""Export decrypted env vars to various formats (shell, JSON, Docker)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Literal

from envcrypt.vault import decrypt_env_file

ExportFormat = Literal["shell", "json", "docker"]


class ExportError(Exception):
    """Raised when export fails."""


def export_env(
    env: Dict[str, str],
    fmt: ExportFormat = "shell",
) -> str:
    """Render a dict of env vars as a string in the requested format."""
    if fmt == "shell":
        return _to_shell(env)
    elif fmt == "json":
        return json.dumps(env, indent=2)
    elif fmt == "docker":
        return _to_docker(env)
    else:
        raise ExportError(f"Unknown export format: {fmt!r}")


def export_vault(
    vault_path: Path,
    identity_path: Path,
    fmt: ExportFormat = "shell",
    output_path: Path | None = None,
) -> str:
    """Decrypt *vault_path* and export its contents in *fmt*.

    Returns the rendered string and optionally writes it to *output_path*.
    """
    env = decrypt_env_file(vault_path, identity_path)
    rendered = export_env(env, fmt)
    if output_path is not None:
        output_path.write_text(rendered, encoding="utf-8")
    return rendered


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _to_shell(env: Dict[str, str]) -> str:
    lines = []
    for key, value in env.items():
        escaped = value.replace('"', '\\"')
        lines.append(f'export {key}="{escaped}"')
    return "\n".join(lines)


def _to_docker(env: Dict[str, str]) -> str:
    """Produce --env-file compatible KEY=VALUE lines (no export prefix)."""
    lines = []
    for key, value in env.items():
        # Docker env-file does not support newlines in values; replace them.
        safe_value = value.replace("\n", " ")
        lines.append(f"{key}={safe_value}")
    return "\n".join(lines)
