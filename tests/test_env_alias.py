"""Tests for envcrypt.env_alias."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_alias import (
    AliasError,
    _aliases_path,
    load_aliases,
    remove_alias,
    resolve_alias,
    save_aliases,
    set_alias,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.touch()
    return p


def test_load_aliases_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_aliases(vault_file) == {}


def test_aliases_file_placed_next_to_vault(vault_file: Path) -> None:
    expected = vault_file.with_suffix(".aliases.json")
    assert _aliases_path(vault_file) == expected


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    mapping = {"db_pass": "DATABASE_PASSWORD", "api": "API_KEY"}
    save_aliases(vault_file, mapping)
    assert load_aliases(vault_file) == mapping


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _aliases_path(vault_file).write_text("not-json")
    with pytest.raises(AliasError, match="Corrupt alias file"):
        load_aliases(vault_file)


def test_load_raises_when_root_is_not_object(vault_file: Path) -> None:
    _aliases_path(vault_file).write_text(json.dumps(["a", "b"]))
    with pytest.raises(AliasError, match="must contain a JSON object"):
        load_aliases(vault_file)


def test_set_alias_creates_new_entry(vault_file: Path) -> None:
    result = set_alias(vault_file, "pw", "DB_PASSWORD")
    assert result == {"pw": "DB_PASSWORD"}
    assert load_aliases(vault_file) == {"pw": "DB_PASSWORD"}


def test_set_alias_overwrites_existing(vault_file: Path) -> None:
    set_alias(vault_file, "pw", "OLD_KEY")
    result = set_alias(vault_file, "pw", "NEW_KEY")
    assert result["pw"] == "NEW_KEY"


def test_set_alias_empty_name_raises(vault_file: Path) -> None:
    with pytest.raises(AliasError, match="must not be empty"):
        set_alias(vault_file, "", "SOME_KEY")


def test_set_alias_empty_real_key_raises(vault_file: Path) -> None:
    with pytest.raises(AliasError, match="must not be empty"):
        set_alias(vault_file, "alias", "")


def test_remove_alias_deletes_entry(vault_file: Path) -> None:
    set_alias(vault_file, "pw", "DB_PASSWORD")
    result = remove_alias(vault_file, "pw")
    assert "pw" not in result


def test_remove_alias_missing_raises(vault_file: Path) -> None:
    with pytest.raises(AliasError, match="not found"):
        remove_alias(vault_file, "ghost")


def test_resolve_alias_returns_real_key(vault_file: Path) -> None:
    set_alias(vault_file, "pw", "DB_PASSWORD")
    assert resolve_alias(vault_file, "pw") == "DB_PASSWORD"


def test_resolve_alias_returns_name_when_no_alias(vault_file: Path) -> None:
    assert resolve_alias(vault_file, "UNKNOWN_KEY") == "UNKNOWN_KEY"
