"""Tests for envcrypt.env_quota."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_quota import (
    QuotaError,
    check_quota,
    load_quota,
    remove_quota,
    save_quota,
    _quota_path,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    f = tmp_path / "secrets.env.age"
    f.write_bytes(b"encrypted")
    return f


def test_load_quota_returns_none_when_no_file(vault_file: Path) -> None:
    assert load_quota(vault_file) is None


def test_quota_file_placed_next_to_vault(vault_file: Path) -> None:
    save_quota(vault_file, 50)
    assert _quota_path(vault_file).exists()


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    save_quota(vault_file, 42)
    assert load_quota(vault_file) == 42


def test_save_quota_rejects_zero(vault_file: Path) -> None:
    with pytest.raises(QuotaError, match="at least 1"):
        save_quota(vault_file, 0)


def test_save_quota_rejects_negative(vault_file: Path) -> None:
    with pytest.raises(QuotaError, match="at least 1"):
        save_quota(vault_file, -5)


def test_load_quota_raises_on_corrupt_json(vault_file: Path) -> None:
    _quota_path(vault_file).write_text("not-json")
    with pytest.raises(QuotaError, match="Corrupt"):
        load_quota(vault_file)


def test_remove_quota_returns_true_when_file_exists(vault_file: Path) -> None:
    save_quota(vault_file, 10)
    assert remove_quota(vault_file) is True
    assert not _quota_path(vault_file).exists()


def test_remove_quota_returns_false_when_no_file(vault_file: Path) -> None:
    assert remove_quota(vault_file) is False


def test_check_quota_passes_when_no_quota_set(vault_file: Path, tmp_path: Path) -> None:
    identity = tmp_path / "id.txt"
    # No quota file — should not raise regardless
    check_quota(vault_file, identity, adding=9999)


def test_check_quota_raises_when_limit_exceeded(vault_file: Path, tmp_path: Path) -> None:
    identity = tmp_path / "id.txt"
    save_quota(vault_file, 3)
    plaintext = "A=1\nB=2\nC=3\n"
    with patch("envcrypt.env_quota.decrypt", return_value=plaintext):
        with pytest.raises(QuotaError, match="Quota exceeded"):
            check_quota(vault_file, identity, adding=1)


def test_check_quota_passes_when_within_limit(vault_file: Path, tmp_path: Path) -> None:
    identity = tmp_path / "id.txt"
    save_quota(vault_file, 5)
    plaintext = "A=1\nB=2\n"
    with patch("envcrypt.env_quota.decrypt", return_value=plaintext):
        check_quota(vault_file, identity, adding=2)  # 2+2=4 <= 5, OK


def test_check_quota_missing_vault_counts_zero(tmp_path: Path) -> None:
    vault = tmp_path / "nonexistent.age"
    identity = tmp_path / "id.txt"
    save_quota(vault, 5)
    # vault does not exist — current key count treated as 0
    check_quota(vault, identity, adding=3)
