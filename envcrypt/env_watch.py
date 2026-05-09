"""Watch a vault file for changes and emit notifications."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


class WatchError(Exception):
    """Raised when vault watching fails."""


@dataclass
class WatchEvent:
    vault: Path
    old_hash: Optional[str]
    new_hash: str
    timestamp: float = field(default_factory=time.time)

    @property
    def is_first_seen(self) -> bool:
        return self.old_hash is None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def watch_vault(
    vault: Path,
    callback: Callable[[WatchEvent], None],
    *,
    interval: float = 2.0,
    max_events: Optional[int] = None,
) -> None:
    """Poll *vault* every *interval* seconds and call *callback* on change.

    Raises WatchError if the vault file does not exist at start.
    Stops after *max_events* callbacks when provided (useful for tests).
    """
    vault = Path(vault)
    if not vault.exists():
        raise WatchError(f"Vault not found: {vault}")

    current_hash: Optional[str] = None
    events_fired = 0

    while True:
        try:
            new_hash = _sha256(vault)
        except OSError as exc:
            raise WatchError(f"Cannot read vault: {exc}") from exc

        if new_hash != current_hash:
            event = WatchEvent(
                vault=vault,
                old_hash=current_hash,
                new_hash=new_hash,
            )
            callback(event)
            current_hash = new_hash
            events_fired += 1
            if max_events is not None and events_fired >= max_events:
                return

        time.sleep(interval)
