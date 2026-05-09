"""Tests for envcrypt.env_pin."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_pin import (
    PinError,
    _pins_path,
    apply_pins,
    list_pinned_keys,
    load_pins,
    pin_key,
    save_pins,
    unpin_key,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


def test_load_pins_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_pins(vault_file) == {}


def test_pins_file_placed_next_to_vault(vault_file: Path) -> None:
    assert _pins_path(vault_file) == vault_file.with_suffix(".pins.json")


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    pins = {"DB_URL": "postgres://localhost/test", "API_KEY": "fixed-key"}
    save_pins(vault_file, pins)
    assert load_pins(vault_file) == pins


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _pins_path(vault_file).write_text("not json")
    with pytest.raises(PinError, match="Corrupt"):
        load_pins(vault_file)


def test_pin_key_adds_entry(vault_file: Path) -> None:
    result = pin_key(vault_file, "SECRET", "abc123")
    assert result == {"SECRET": "abc123"}
    assert load_pins(vault_file)["SECRET"] == "abc123"


def test_pin_key_overwrites_existing(vault_file: Path) -> None:
    pin_key(vault_file, "SECRET", "old")
    pin_key(vault_file, "SECRET", "new")
    assert load_pins(vault_file)["SECRET"] == "new"


def test_unpin_key_removes_entry(vault_file: Path) -> None:
    pin_key(vault_file, "SECRET", "val")
    unpin_key(vault_file, "SECRET")
    assert "SECRET" not in load_pins(vault_file)


def test_unpin_key_raises_when_not_pinned(vault_file: Path) -> None:
    with pytest.raises(PinError, match="not pinned"):
        unpin_key(vault_file, "MISSING")


def test_apply_pins_overrides_env(vault_file: Path) -> None:
    env = {"DB_URL": "postgres://prod", "OTHER": "value"}
    pins = {"DB_URL": "postgres://test"}
    result = apply_pins(env, pins)
    assert result["DB_URL"] == "postgres://test"
    assert result["OTHER"] == "value"


def test_apply_pins_adds_missing_keys(vault_file: Path) -> None:
    env: dict = {}
    pins = {"NEW_KEY": "forced"}
    result = apply_pins(env, pins)
    assert result["NEW_KEY"] == "forced"


def test_list_pinned_keys_returns_sorted(vault_file: Path) -> None:
    pin_key(vault_file, "Z_KEY", "1")
    pin_key(vault_file, "A_KEY", "2")
    assert list_pinned_keys(vault_file) == ["A_KEY", "Z_KEY"]
