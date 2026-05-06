"""Search and filter keys across encrypted .env vault files."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from envcrypt.vault import decrypt_env_file


class SearchError(Exception):
    """Raised when a search operation fails."""


@dataclass
class SearchMatch:
    key: str
    value: str
    vault_file: Path

    def __str__(self) -> str:
        return f"{self.vault_file}::{self.key}={self.value}"


@dataclass
class SearchResult:
    matches: List[SearchMatch] = field(default_factory=list)
    searched_files: int = 0

    @property
    def total(self) -> int:
        return len(self.matches)


def search_vault(
    vault_file: Path,
    identity_file: Path,
    pattern: str,
    *,
    search_values: bool = False,
    case_sensitive: bool = False,
    use_regex: bool = False,
) -> SearchResult:
    """Search keys (and optionally values) in a single vault file."""
    try:
        env: Dict[str, str] = decrypt_env_file(vault_file, identity_file)
    except Exception as exc:
        raise SearchError(f"Failed to decrypt {vault_file}: {exc}") from exc

    flags = 0 if case_sensitive else re.IGNORECASE
    result = SearchResult(searched_files=1)

    for key, value in env.items():
        matched = _matches(key, pattern, flags, use_regex)
        if not matched and search_values:
            matched = _matches(value, pattern, flags, use_regex)
        if matched:
            result.matches.append(SearchMatch(key=key, value=value, vault_file=vault_file))

    return result


def search_vaults(
    vault_files: List[Path],
    identity_file: Path,
    pattern: str,
    *,
    search_values: bool = False,
    case_sensitive: bool = False,
    use_regex: bool = False,
) -> SearchResult:
    """Search across multiple vault files."""
    combined = SearchResult()
    for vault_file in vault_files:
        partial = search_vault(
            vault_file,
            identity_file,
            pattern,
            search_values=search_values,
            case_sensitive=case_sensitive,
            use_regex=use_regex,
        )
        combined.matches.extend(partial.matches)
        combined.searched_files += 1
    return combined


def _matches(text: str, pattern: str, flags: int, use_regex: bool) -> bool:
    if use_regex:
        return bool(re.search(pattern, text, flags))
    if not (flags & re.IGNORECASE):
        return fnmatch.fnmatchcase(text, pattern)
    return fnmatch.fnmatchcase(text.lower(), pattern.lower())
