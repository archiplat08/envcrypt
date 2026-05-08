"""Attach and retrieve inline documentation comments for .env keys."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional


class DocsError(Exception):
    """Raised when a documentation operation fails."""


def _docs_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".docs.json")


def load_docs(vault_path: Path) -> Dict[str, str]:
    """Return the key->doc mapping for *vault_path*.

    Returns an empty dict when no docs file exists yet.
    """
    path = _docs_path(vault_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DocsError(f"Corrupt docs file {path}: {exc}") from exc


def save_docs(vault_path: Path, docs: Dict[str, str]) -> None:
    """Persist *docs* next to *vault_path*."""
    path = _docs_path(vault_path)
    path.write_text(json.dumps(docs, indent=2, sort_keys=True), encoding="utf-8")


def set_doc(vault_path: Path, key: str, doc: str) -> None:
    """Set or update the documentation string for *key*."""
    if not key.strip():
        raise DocsError("Key must not be empty.")
    docs = load_docs(vault_path)
    docs[key] = doc
    save_docs(vault_path, docs)


def remove_doc(vault_path: Path, key: str) -> bool:
    """Remove the documentation entry for *key*.

    Returns True when an entry was removed, False when the key was not found.
    """
    docs = load_docs(vault_path)
    if key not in docs:
        return False
    del docs[key]
    save_docs(vault_path, docs)
    return True


def get_doc(vault_path: Path, key: str) -> Optional[str]:
    """Return the documentation string for *key*, or None if absent."""
    return load_docs(vault_path).get(key)
