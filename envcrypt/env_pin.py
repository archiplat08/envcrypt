"""Pin specific env keys to fixed values, preventing them from being overwritten."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


class PinError(Exception):
    pass


def _pins_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".pins.json")


def load_pins(vault_path: Path) -> Dict[str, str]:
    """Load pinned keys from the sidecar file. Returns empty dict if not found."""
    p = _pins_path(vault_path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise PinError(f"Corrupt pins file {p}: {exc}") from exc


def save_pins(vault_path: Path, pins: Dict[str, str]) -> None:
    """Persist pinned keys to the sidecar file."""
    _pins_path(vault_path).write_text(json.dumps(pins, indent=2))


def pin_key(vault_path: Path, key: str, value: str) -> Dict[str, str]:
    """Pin *key* to *value*. Returns updated pins mapping."""
    pins = load_pins(vault_path)
    pins[key] = value
    save_pins(vault_path, pins)
    return pins


def unpin_key(vault_path: Path, key: str) -> Dict[str, str]:
    """Remove pin for *key*. Raises PinError if key is not pinned."""
    pins = load_pins(vault_path)
    if key not in pins:
        raise PinError(f"Key '{key}' is not pinned")
    del pins[key]
    save_pins(vault_path, pins)
    return pins


def apply_pins(env: Dict[str, str], pins: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of *env* with all pinned keys forced to their pinned values."""
    result = dict(env)
    result.update(pins)
    return result


def list_pinned_keys(vault_path: Path) -> List[str]:
    """Return sorted list of pinned key names."""
    return sorted(load_pins(vault_path).keys())
