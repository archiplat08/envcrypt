"""Vault quota enforcement — limit the number of keys stored in a vault."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from envcrypt.crypto import decrypt
from envcrypt.dotenv import parse_dotenv


class QuotaError(Exception):
    """Raised when a quota operation fails."""


DEFAULT_QUOTA = 100


def _quota_path(vault: Path) -> Path:
    return vault.with_suffix(".quota.json")


def load_quota(vault: Path) -> Optional[int]:
    """Return the configured key quota for *vault*, or None if not set."""
    path = _quota_path(vault)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return int(data["limit"])
    except Exception as exc:
        raise QuotaError(f"Corrupt quota file: {exc}") from exc


def save_quota(vault: Path, limit: int) -> None:
    """Persist a key quota *limit* for *vault*."""
    if limit < 1:
        raise QuotaError("Quota limit must be at least 1.")
    _quota_path(vault).write_text(json.dumps({"limit": limit}))


def remove_quota(vault: Path) -> bool:
    """Remove the quota for *vault*. Returns True if a file was deleted."""
    path = _quota_path(vault)
    if path.exists():
        path.unlink()
        return True
    return False


def check_quota(
    vault: Path,
    identity: Path,
    *,
    adding: int = 1,
) -> None:
    """Raise *QuotaError* if adding *adding* keys would exceed the quota.

    Does nothing when no quota is configured.
    """
    limit = load_quota(vault)
    if limit is None:
        return
    if not vault.exists():
        current = 0
    else:
        plaintext = decrypt(vault, identity)
        current = len(parse_dotenv(plaintext))
    if current + adding > limit:
        raise QuotaError(
            f"Quota exceeded: vault has {current} key(s), limit is {limit}, "
            f"cannot add {adding} more."
        )
