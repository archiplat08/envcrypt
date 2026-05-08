"""Tests for envcrypt.env_chmod."""

import json
import pytest
from pathlib import Path

from envcrypt.env_chmod import (
    ChmodError,
    KeyPermission,
    load_permissions,
    save_permissions,
    set_permission,
    remove_permission,
    is_allowed,
    _perms_path,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.age"
    p.write_bytes(b"fake-vault")
    return p


def test_load_permissions_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_permissions(vault_file) == {}


def test_perms_file_placed_next_to_vault(vault_file: Path) -> None:
    assert _perms_path(vault_file) == vault_file.with_suffix(".perms.json")


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    perms = {
        "DB_PASSWORD": KeyPermission(
            key="DB_PASSWORD",
            allowed_recipients=["age1abc", "age1def"],
        )
    }
    save_permissions(vault_file, perms)
    loaded = load_permissions(vault_file)
    assert "DB_PASSWORD" in loaded
    assert loaded["DB_PASSWORD"].allowed_recipients == ["age1abc", "age1def"]
    assert loaded["DB_PASSWORD"].deny_all is False


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _perms_path(vault_file).write_text("{not valid json")
    with pytest.raises(ChmodError, match="Corrupt"):
        load_permissions(vault_file)


def test_set_permission_creates_entry(vault_file: Path) -> None:
    perm = set_permission(vault_file, "API_KEY", allowed_recipients=["age1xyz"])
    assert perm.key == "API_KEY"
    assert "age1xyz" in perm.allowed_recipients
    loaded = load_permissions(vault_file)
    assert "API_KEY" in loaded


def test_set_permission_deny_all(vault_file: Path) -> None:
    perm = set_permission(vault_file, "SECRET", deny_all=True)
    assert perm.deny_all is True


def test_set_permission_missing_vault_raises(tmp_path: Path) -> None:
    with pytest.raises(ChmodError, match="Vault not found"):
        set_permission(tmp_path / "missing.age", "KEY")


def test_remove_permission_returns_true_when_exists(vault_file: Path) -> None:
    set_permission(vault_file, "REMOVE_ME", allowed_recipients=["age1aaa"])
    assert remove_permission(vault_file, "REMOVE_ME") is True
    assert "REMOVE_ME" not in load_permissions(vault_file)


def test_remove_permission_returns_false_when_not_exists(vault_file: Path) -> None:
    assert remove_permission(vault_file, "GHOST_KEY") is False


def test_is_allowed_open_by_default(vault_file: Path) -> None:
    assert is_allowed(vault_file, "OPEN_KEY", "age1anyone") is True


def test_is_allowed_with_explicit_allow_list(vault_file: Path) -> None:
    set_permission(vault_file, "RESTRICTED", allowed_recipients=["age1good"])
    assert is_allowed(vault_file, "RESTRICTED", "age1good") is True
    assert is_allowed(vault_file, "RESTRICTED", "age1bad") is False


def test_is_allowed_deny_all_blocks_everyone(vault_file: Path) -> None:
    set_permission(vault_file, "TOP_SECRET", deny_all=True)
    assert is_allowed(vault_file, "TOP_SECRET", "age1anyone") is False
