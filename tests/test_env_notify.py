"""Tests for envcrypt.env_notify."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_notify import (
    NotifyError,
    HookConfig,
    _hooks_path,
    add_hook,
    fire_hooks,
    load_hooks,
    remove_hook,
    save_hooks,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


def test_load_hooks_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_hooks(vault_file) == []


def test_hooks_file_placed_next_to_vault(vault_file: Path) -> None:
    assert _hooks_path(vault_file) == vault_file.parent / "secrets.hooks.json"


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    hooks = [HookConfig(event="encrypt", command="echo {event}"), HookConfig(event="rotate", command="notify-send done", enabled=False)]
    save_hooks(vault_file, hooks)
    loaded = load_hooks(vault_file)
    assert len(loaded) == 2
    assert loaded[0].event == "encrypt"
    assert loaded[1].enabled is False


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _hooks_path(vault_file).write_text("not-json")
    with pytest.raises(NotifyError, match="Corrupt"):
        load_hooks(vault_file)


def test_add_hook_appends_entry(vault_file: Path) -> None:
    add_hook(vault_file, "encrypt", "echo encrypted")
    hooks = load_hooks(vault_file)
    assert len(hooks) == 1
    assert hooks[0].command == "echo encrypted"


def test_add_hook_multiple_events(vault_file: Path) -> None:
    add_hook(vault_file, "encrypt", "echo enc")
    add_hook(vault_file, "rotate", "echo rot")
    hooks = load_hooks(vault_file)
    assert len(hooks) == 2


def test_remove_hook_deletes_by_event(vault_file: Path) -> None:
    add_hook(vault_file, "encrypt", "echo enc")
    add_hook(vault_file, "rotate", "echo rot")
    remaining = remove_hook(vault_file, "encrypt")
    assert all(h.event != "encrypt" for h in remaining)
    assert len(remaining) == 1


def test_remove_hook_noop_when_event_missing(vault_file: Path) -> None:
    add_hook(vault_file, "rotate", "echo rot")
    remaining = remove_hook(vault_file, "encrypt")
    assert len(remaining) == 1


def test_fire_hooks_runs_enabled_hooks(vault_file: Path) -> None:
    add_hook(vault_file, "encrypt", "true")
    with patch("envcrypt.env_notify.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        count = fire_hooks(vault_file, "encrypt")
    assert count == 1
    mock_run.assert_called_once()


def test_fire_hooks_skips_disabled_hooks(vault_file: Path) -> None:
    hooks = [HookConfig(event="encrypt", command="true", enabled=False)]
    save_hooks(vault_file, hooks)
    with patch("envcrypt.env_notify.subprocess.run") as mock_run:
        count = fire_hooks(vault_file, "encrypt")
    assert count == 0
    mock_run.assert_not_called()


def test_fire_hooks_raises_on_nonzero_exit(vault_file: Path) -> None:
    add_hook(vault_file, "rotate", "false")
    with patch("envcrypt.env_notify.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        with pytest.raises(NotifyError, match="exited with code"):
            fire_hooks(vault_file, "rotate")


def test_fire_hooks_substitutes_vault_and_event(vault_file: Path) -> None:
    add_hook(vault_file, "share", "echo {vault} {event}")
    with patch("envcrypt.env_notify.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        fire_hooks(vault_file, "share")
    called_cmd = mock_run.call_args[0][0]
    assert str(vault_file) in called_cmd
    assert "share" in called_cmd
