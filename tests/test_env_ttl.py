"""Tests for envcrypt.env_ttl."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_ttl import (
    TtlError,
    is_expired,
    list_ttl,
    load_ttl,
    remove_ttl,
    seconds_remaining,
    set_ttl,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    v = tmp_path / "secrets.env.age"
    v.write_bytes(b"encrypted")
    return v


def test_load_ttl_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_ttl(vault_file) == {}


def test_ttl_file_placed_next_to_vault(vault_file: Path) -> None:
    set_ttl(vault_file, "MY_KEY", 60)
    expected = vault_file.with_suffix(".ttl.json")
    assert expected.exists()


def test_set_ttl_stores_expiry(vault_file: Path) -> None:
    expiry_iso = set_ttl(vault_file, "API_KEY", 3600)
    ttl_map = load_ttl(vault_file)
    assert "API_KEY" in ttl_map
    assert ttl_map["API_KEY"] == expiry_iso


def test_set_ttl_rejects_zero_seconds(vault_file: Path) -> None:
    with pytest.raises(TtlError, match="positive"):
        set_ttl(vault_file, "KEY", 0)


def test_set_ttl_rejects_negative_seconds(vault_file: Path) -> None:
    with pytest.raises(TtlError, match="positive"):
        set_ttl(vault_file, "KEY", -10)


def test_seconds_remaining_none_when_no_ttl(vault_file: Path) -> None:
    assert seconds_remaining(vault_file, "MISSING_KEY") is None


def test_seconds_remaining_positive_for_future(vault_file: Path) -> None:
    set_ttl(vault_file, "DB_PASS", 3600)
    remaining = seconds_remaining(vault_file, "DB_PASS")
    assert remaining is not None
    assert 3590 < remaining <= 3600


def test_is_expired_false_for_future_key(vault_file: Path) -> None:
    set_ttl(vault_file, "TOKEN", 3600)
    assert not is_expired(vault_file, "TOKEN")


def test_is_expired_true_for_past_timestamp(vault_file: Path, tmp_path: Path) -> None:
    ttl_path = vault_file.with_suffix(".ttl.json")
    ttl_path.write_text(json.dumps({"OLD_KEY": "2000-01-01T00:00:00+00:00"}))
    assert is_expired(vault_file, "OLD_KEY")


def test_is_expired_false_when_key_absent(vault_file: Path) -> None:
    assert not is_expired(vault_file, "NO_SUCH_KEY")


def test_remove_ttl_returns_true_when_removed(vault_file: Path) -> None:
    set_ttl(vault_file, "MY_KEY", 60)
    assert remove_ttl(vault_file, "MY_KEY") is True
    assert "MY_KEY" not in load_ttl(vault_file)


def test_remove_ttl_returns_false_when_missing(vault_file: Path) -> None:
    assert remove_ttl(vault_file, "GHOST") is False


def test_list_ttl_returns_all_entries(vault_file: Path) -> None:
    set_ttl(vault_file, "A", 60)
    set_ttl(vault_file, "B", 120)
    result = list_ttl(vault_file)
    assert set(result.keys()) == {"A", "B"}


def test_load_ttl_raises_on_corrupt_json(vault_file: Path) -> None:
    ttl_path = vault_file.with_suffix(".ttl.json")
    ttl_path.write_text("not json{{{")
    with pytest.raises(TtlError, match="Corrupt"):
        load_ttl(vault_file)
