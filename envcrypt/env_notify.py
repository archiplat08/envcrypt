"""Notification hooks for vault events (e.g. encrypt, rotate, share)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


class NotifyError(Exception):
    """Raised when a notification hook fails."""


@dataclass
class HookConfig:
    event: str          # e.g. "encrypt", "rotate", "share"
    command: str        # shell command template; {vault} and {event} are substituted
    enabled: bool = True


def _hooks_path(vault_path: Path) -> Path:
    return vault_path.parent / (vault_path.stem + ".hooks.json")


def load_hooks(vault_path: Path) -> List[HookConfig]:
    """Load hook configurations for *vault_path*."""
    p = _hooks_path(vault_path)
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise NotifyError(f"Corrupt hooks file {p}: {exc}") from exc
    return [
        HookConfig(event=h["event"], command=h["command"], enabled=h.get("enabled", True))
        for h in raw
    ]


def save_hooks(vault_path: Path, hooks: List[HookConfig]) -> None:
    """Persist *hooks* next to *vault_path*."""
    p = _hooks_path(vault_path)
    p.write_text(
        json.dumps([{"event": h.event, "command": h.command, "enabled": h.enabled} for h in hooks],
                   indent=2)
    )


def add_hook(vault_path: Path, event: str, command: str) -> List[HookConfig]:
    """Append a new hook and persist; returns the updated list."""
    hooks = load_hooks(vault_path)
    hooks.append(HookConfig(event=event, command=command))
    save_hooks(vault_path, hooks)
    return hooks


def remove_hook(vault_path: Path, event: str) -> List[HookConfig]:
    """Remove all hooks for *event* and persist; returns the updated list."""
    hooks = [h for h in load_hooks(vault_path) if h.event != event]
    save_hooks(vault_path, hooks)
    return hooks


def fire_hooks(vault_path: Path, event: str, actor: Optional[str] = None) -> int:
    """Run all enabled hooks matching *event*; returns the number of hooks fired."""
    hooks = [h for h in load_hooks(vault_path) if h.event == event and h.enabled]
    for hook in hooks:
        cmd = hook.command.replace("{vault}", str(vault_path)).replace("{event}", event)
        if actor:
            cmd = cmd.replace("{actor}", actor)
        result = subprocess.run(cmd, shell=True)  # noqa: S602
        if result.returncode != 0:
            raise NotifyError(
                f"Hook for event '{event}' exited with code {result.returncode}: {cmd}"
            )
    return len(hooks)
