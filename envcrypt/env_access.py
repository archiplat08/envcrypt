"""Access control log for vault key reads and writes."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


class AccessError(Exception):
    pass


@dataclass
class AccessEntry:
    action: str          # 'read' | 'write' | 'delete'
    key: str
    actor: Optional[str]
    timestamp: str

    def __str__(self) -> str:
        actor_part = f" by {self.actor}" if self.actor else ""
        return f"[{self.timestamp}] {self.action.upper()} {self.key}{actor_part}"


def _access_log_path(vault_path: Path) -> Path:
    return vault_path.parent / (vault_path.stem + ".access.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_access_log(vault_path: Path) -> List[AccessEntry]:
    log_path = _access_log_path(vault_path)
    if not log_path.exists():
        return []
    try:
        data = json.loads(log_path.read_text())
        return [AccessEntry(**e) for e in data]
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        raise AccessError(f"Corrupt access log: {exc}") from exc


def record_access(
    vault_path: Path,
    action: str,
    key: str,
    actor: Optional[str] = None,
) -> AccessEntry:
    if action not in ("read", "write", "delete"):
        raise AccessError(f"Invalid action: {action!r}")
    entry = AccessEntry(action=action, key=key, actor=actor, timestamp=_now_iso())
    log_path = _access_log_path(vault_path)
    entries = load_access_log(vault_path)
    entries.append(entry)
    log_path.write_text(json.dumps([asdict(e) for e in entries], indent=2))
    return entry


def clear_access_log(vault_path: Path) -> int:
    log_path = _access_log_path(vault_path)
    if not log_path.exists():
        return 0
    count = len(load_access_log(vault_path))
    log_path.unlink()
    return count


def filter_access_log(
    vault_path: Path,
    action: Optional[str] = None,
    key: Optional[str] = None,
    actor: Optional[str] = None,
) -> List[AccessEntry]:
    entries = load_access_log(vault_path)
    if action:
        entries = [e for e in entries if e.action == action]
    if key:
        entries = [e for e in entries if e.key == key]
    if actor:
        entries = [e for e in entries if e.actor == actor]
    return entries
