"""Tests for envcrypt.env_expire."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from envcrypt.env_expire import (
    ExpireError,
    ExpiryInfo,
    list_expired,
    load_expiry,
    remove_expiry,
    save_expiry,
    set_expiry,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"dummy")
    return p


def _future(days: int = 30) -> str:
    return (datetime.now(tz=timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()


def test_load_expiry_returns_empty_when_no_file(vault_file: Path) -> None:
    result = load_expiry(vault_file)
    assert result == {}


def test_set_expiry_creates_entry(vault_file: Path) -> None:
    info = set_expiry(vault_file, "MY_SECRET", _future(), note="rotate soon")
    assert info.key == "MY_SECRET"
    assert not info.is_expired()


def test_set_expiry_persists(vault_file: Path) -> None:
    set_expiry(vault_file, "DB_PASS", _future(10))
    loaded = load_expiry(vault_file)
    assert "DB_PASS" in loaded
    assert loaded["DB_PASS"].days_remaining() > 9


def test_set_expiry_invalid_date_raises(vault_file: Path) -> None:
    with pytest.raises(ExpireError, match="Invalid date format"):
        set_expiry(vault_file, "KEY", "not-a-date")


def test_is_expired_true_for_past_date(vault_file: Path) -> None:
    set_expiry(vault_file, "OLD_KEY", _past(5))
    loaded = load_expiry(vault_file)
    assert loaded["OLD_KEY"].is_expired()


def test_is_expired_false_for_future_date(vault_file: Path) -> None:
    info = ExpiryInfo(key="K", expires_at=_future(10))
    assert not info.is_expired()


def test_remove_expiry_returns_true_when_found(vault_file: Path) -> None:
    set_expiry(vault_file, "TMP", _future())
    assert remove_expiry(vault_file, "TMP") is True
    assert "TMP" not in load_expiry(vault_file)


def test_remove_expiry_returns_false_when_missing(vault_file: Path) -> None:
    assert remove_expiry(vault_file, "GHOST") is False


def test_list_expired_returns_only_past_keys(vault_file: Path) -> None:
    set_expiry(vault_file, "ALIVE", _future(5))
    set_expiry(vault_file, "DEAD", _past(2))
    expired = list_expired(vault_file)
    keys = [e.key for e in expired]
    assert "DEAD" in keys
    assert "ALIVE" not in keys


def test_load_expiry_raises_on_corrupt_json(vault_file: Path) -> None:
    expiry_path = vault_file.with_suffix(".expiry.json")
    expiry_path.write_text("{bad json")
    with pytest.raises(ExpireError, match="Corrupt expiry file"):
        load_expiry(vault_file)


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    expiry_map = {
        "API_KEY": ExpiryInfo(key="API_KEY", expires_at=_future(7), note="weekly")
    }
    save_expiry(vault_file, expiry_map)
    loaded = load_expiry(vault_file)
    assert loaded["API_KEY"].note == "weekly"
