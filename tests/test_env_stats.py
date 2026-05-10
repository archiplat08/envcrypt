"""Tests for envcrypt.env_stats."""
from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_stats import StatsError, VaultStats, compute_stats


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    f = tmp_path / "secrets.env.age"
    f.write_bytes(b"encrypted")
    return f


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    f = tmp_path / "key.txt"
    f.write_text("AGE-SECRET-KEY-1...")
    return f


def _patch_decrypt(env: dict):
    return patch("envcrypt.env_stats.decrypt_env_file", return_value=env)


def test_compute_stats_basic_counts(vault_file, identity_file):
    env = {"DB_PASSWORD": "s3cr3t", "APP_NAME": "myapp", "API_KEY": "abc123", "DEBUG": ""}
    with _patch_decrypt(env):
        stats = compute_stats(vault_file, identity_file)

    assert stats.total_keys == 4
    assert stats.sensitive_keys == 2  # DB_PASSWORD, API_KEY
    assert stats.non_sensitive_keys == 2
    assert stats.empty_values == 1  # DEBUG


def test_compute_stats_unique_prefixes(vault_file, identity_file):
    env = {"DB_HOST": "localhost", "DB_PORT": "5432", "APP_ENV": "prod"}
    with _patch_decrypt(env):
        stats = compute_stats(vault_file, identity_file)

    assert "DB" in stats.unique_prefixes
    assert "APP" in stats.unique_prefixes
    assert len(stats.unique_prefixes) == 2


def test_compute_stats_longest_key(vault_file, identity_file):
    env = {"SHORT": "a", "A_VERY_LONG_KEY_NAME": "b"}
    with _patch_decrypt(env):
        stats = compute_stats(vault_file, identity_file)

    assert stats.longest_key == "A_VERY_LONG_KEY_NAME"


def test_compute_stats_longest_value_key(vault_file, identity_file):
    env = {"SMALL": "hi", "BIG": "a" * 100}
    with _patch_decrypt(env):
        stats = compute_stats(vault_file, identity_file)

    assert stats.longest_value_key == "BIG"


def test_compute_stats_empty_vault(vault_file, identity_file):
    with _patch_decrypt({}):
        stats = compute_stats(vault_file, identity_file)

    assert stats.total_keys == 0
    assert stats.sensitive_keys == 0
    assert stats.empty_values == 0
    assert stats.unique_prefixes == []
    assert stats.longest_key == ""


def test_compute_stats_missing_vault(tmp_path, identity_file):
    with pytest.raises(StatsError, match="Vault not found"):
        compute_stats(tmp_path / "missing.age", identity_file)


def test_compute_stats_missing_identity(vault_file, tmp_path):
    with pytest.raises(StatsError, match="Identity file not found"):
        compute_stats(vault_file, tmp_path / "missing.txt")


def test_summary_output(vault_file, identity_file):
    env = {"SECRET_KEY": "val", "HOST": "localhost"}
    with _patch_decrypt(env):
        stats = compute_stats(vault_file, identity_file)

    summary = stats.summary()
    assert "Total keys" in summary
    assert "Sensitive keys" in summary
    assert "Longest key" in summary
