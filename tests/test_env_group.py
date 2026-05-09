"""Tests for envcrypt.env_group."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_group import (
    GroupError,
    _groups_path,
    add_key_to_group,
    delete_group,
    groups_for_key,
    keys_in_group,
    load_groups,
    remove_key_from_group,
    save_groups,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"")
    return p


def test_load_groups_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_groups(vault_file) == {}


def test_groups_file_placed_next_to_vault(vault_file: Path) -> None:
    assert _groups_path(vault_file) == vault_file.with_suffix(".groups.json")


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    data = {"backend": ["DB_URL", "DB_PASS"], "frontend": ["API_KEY"]}
    save_groups(vault_file, data)
    assert load_groups(vault_file) == data


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _groups_path(vault_file).write_text("not json")
    with pytest.raises(GroupError, match="Corrupt"):
        load_groups(vault_file)


def test_add_key_to_group_creates_group(vault_file: Path) -> None:
    groups = add_key_to_group(vault_file, "backend", "DB_URL")
    assert "backend" in groups
    assert "DB_URL" in groups["backend"]


def test_add_key_to_group_no_duplicate(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    groups = add_key_to_group(vault_file, "backend", "DB_URL")
    assert groups["backend"].count("DB_URL") == 1


def test_remove_key_from_group_success(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    add_key_to_group(vault_file, "backend", "DB_PASS")
    groups = remove_key_from_group(vault_file, "backend", "DB_URL")
    assert "DB_URL" not in groups["backend"]
    assert "DB_PASS" in groups["backend"]


def test_remove_last_key_deletes_group(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    groups = remove_key_from_group(vault_file, "backend", "DB_URL")
    assert "backend" not in groups


def test_remove_key_missing_group_raises(vault_file: Path) -> None:
    with pytest.raises(GroupError, match="does not exist"):
        remove_key_from_group(vault_file, "ghost", "KEY")


def test_remove_key_not_in_group_raises(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    with pytest.raises(GroupError, match="not in group"):
        remove_key_from_group(vault_file, "backend", "MISSING")


def test_delete_group_success(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    delete_group(vault_file, "backend")
    assert load_groups(vault_file) == {}


def test_delete_group_missing_raises(vault_file: Path) -> None:
    with pytest.raises(GroupError, match="does not exist"):
        delete_group(vault_file, "ghost")


def test_keys_in_group_returns_members(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    add_key_to_group(vault_file, "backend", "DB_PASS")
    assert set(keys_in_group(vault_file, "backend")) == {"DB_URL", "DB_PASS"}


def test_keys_in_group_missing_raises(vault_file: Path) -> None:
    with pytest.raises(GroupError, match="does not exist"):
        keys_in_group(vault_file, "ghost")


def test_groups_for_key_returns_correct_groups(vault_file: Path) -> None:
    add_key_to_group(vault_file, "backend", "DB_URL")
    add_key_to_group(vault_file, "infra", "DB_URL")
    add_key_to_group(vault_file, "frontend", "API_KEY")
    result = groups_for_key(vault_file, "DB_URL")
    assert set(result) == {"backend", "infra"}


def test_groups_for_key_no_groups_returns_empty(vault_file: Path) -> None:
    assert groups_for_key(vault_file, "ORPHAN") == []
