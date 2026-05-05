"""Simple audit log for envcrypt operations."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

AUDIT_LOG_FILE = ".env.audit.log"

OperationType = Literal["encrypt", "decrypt", "key_generate", "recipient_add", "recipient_remove"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record(
    operation: OperationType,
    detail: str,
    log_path: str | Path = AUDIT_LOG_FILE,
    actor: Optional[str] = None,
) -> dict:
    """Append an audit entry to *log_path* and return the entry."""
    entry = {
        "timestamp": _now_iso(),
        "operation": operation,
        "detail": detail,
    }
    if actor:
        entry["actor"] = actor

    log_file = Path(log_path)
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")

    return entry


def read_log(log_path: str | Path = AUDIT_LOG_FILE) -> list[dict]:
    """Return all audit entries from *log_path* as a list of dicts."""
    log_file = Path(log_path)
    if not log_file.exists():
        return []
    entries = []
    with log_file.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries
