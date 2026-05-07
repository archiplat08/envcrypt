"""Tests for envcrypt.env_filter."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_filter import FilterError, FilterResult, filter_env, filter_vault


# ---------------------------------------------------------------------------
# filter_env unit tests
# ---------------------------------------------------------------------------

SAMPLE = {
    "DB_HOST": "localhost",
    "DB_PORT": "5432",
    "APP_SECRET": "s3cr3t",
    "APP_DEBUG": "true",
    "LOG_LEVEL": "info",
}


def test_filter_env_by_prefix():
    result = filter_env(SAMPLE, prefix="DB_")
    assert set(result.matched.keys()) == {"DB_HOST", "DB_PORT"}
    assert "APP_SECRET" in result.excluded


def test_filter_env_by_glob_pattern():
    result = filter_env(SAMPLE, pattern="APP_*")
    assert set(result.matched.keys()) == {"APP_SECRET", "APP_DEBUG"}


def test_filter_env_by_exact_pattern():
    result = filter_env(SAMPLE, pattern="LOG_LEVEL")
    assert result.matched == {"LOG_LEVEL": "info"}


def test_filter_env_no_criteria_returns_all():
    result = filter_env(SAMPLE)
    assert result.matched == SAMPLE
    assert result.excluded == []


def test_filter_env_by_tag():
    tag_map = {"APP_SECRET": ["sensitive"], "DB_HOST": ["infra"]}
    result = filter_env(SAMPLE, tags=["sensitive"], tag_map=tag_map)
    assert result.matched == {"APP_SECRET": "s3cr3t"}


def test_filter_env_prefix_and_pattern_combined():
    result = filter_env(SAMPLE, prefix="APP_", pattern="APP_*DEBUG*")
    assert result.matched == {"APP_DEBUG": "true"}


def test_filter_result_count_and_summary():
    result = FilterResult(matched={"A": "1", "B": "2"}, excluded=["C"])
    assert result.count == 2
    assert "2 key(s) matched" in result.summary()
    assert "1 excluded" in result.summary()


# ---------------------------------------------------------------------------
# filter_vault integration tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-FAKE")
    return p


def _patch_decrypt(content: str):
    return patch("envcrypt.env_filter.decrypt", return_value=content)


def test_filter_vault_success(vault_file, identity_file):
    plaintext = "DB_HOST=localhost\nDB_PORT=5432\nAPP_KEY=secret\n"
    with _patch_decrypt(plaintext):
        result = filter_vault(vault_file, identity_file, prefix="DB_")
    assert set(result.matched.keys()) == {"DB_HOST", "DB_PORT"}


def test_filter_vault_missing_vault_raises(tmp_path, identity_file):
    with pytest.raises(FilterError, match="Vault file not found"):
        filter_vault(tmp_path / "missing.age", identity_file)


def test_filter_vault_missing_identity_raises(vault_file, tmp_path):
    with pytest.raises(FilterError, match="Identity file not found"):
        filter_vault(vault_file, tmp_path / "missing.txt")


def test_filter_vault_decrypt_failure_raises(vault_file, identity_file):
    with patch("envcrypt.env_filter.decrypt", side_effect=RuntimeError("bad key")):
        with pytest.raises(FilterError, match="Failed to decrypt vault"):
            filter_vault(vault_file, identity_file)
