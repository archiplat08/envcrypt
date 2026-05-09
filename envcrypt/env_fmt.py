"""Formatting / pretty-print utilities for vault env files."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.vault import encrypt_env_file


class FmtError(Exception):
    """Raised when formatting fails."""


@dataclass
class FmtResult:
    original: str
    formatted: str
    changed: bool
    sorted_keys: bool
    normalized_quotes: bool

    def summary(self) -> str:
        if not self.changed:
            return "Already formatted — no changes made."
        parts: List[str] = []
        if self.sorted_keys:
            parts.append("sorted keys")
        if self.normalized_quotes:
            parts.append("normalized quotes")
        return "Formatted: " + ", ".join(parts) + "."


def _normalize_value(value: str) -> str:
    """Strip surrounding quotes that were preserved literally in the raw value."""
    for quote in ('"', "'"):
        if value.startswith(quote) and value.endswith(quote) and len(value) >= 2:
            return value[1:-1]
    return value


def format_env(
    env: Dict[str, str],
    *,
    sort_keys: bool = True,
    normalize_quotes: bool = True,
) -> Dict[str, str]:
    """Return a formatted copy of *env*."""
    result = {k: (_normalize_value(v) if normalize_quotes else v) for k, v in env.items()}
    if sort_keys:
        result = dict(sorted(result.items()))
    return result


def format_vault(
    vault_path: Path,
    identity_path: Path,
    recipients_path: Path,
    *,
    sort_keys: bool = True,
    normalize_quotes: bool = True,
    dry_run: bool = False,
) -> FmtResult:
    """Decrypt *vault_path*, reformat, and re-encrypt in place."""
    if not vault_path.exists():
        raise FmtError(f"Vault file not found: {vault_path}")

    raw = decrypt(str(vault_path), str(identity_path))
    original_text = raw

    env = parse_dotenv(raw)
    formatted_env = format_env(env, sort_keys=sort_keys, normalize_quotes=normalize_quotes)
    formatted_text = serialize_dotenv(formatted_env)

    changed = formatted_text != original_text

    if changed and not dry_run:
        tmp = vault_path.with_suffix(".fmt.tmp.env")
        try:
            tmp.write_text(formatted_text)
            encrypt_env_file(tmp, recipients_path, output_path=vault_path)
        finally:
            if tmp.exists():
                tmp.unlink()

    return FmtResult(
        original=original_text,
        formatted=formatted_text,
        changed=changed,
        sorted_keys=sort_keys,
        normalized_quotes=normalize_quotes,
    )
