"""Tests for envcrypt.search module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.search import SearchError, SearchMatch, search_vault, search_vaults


VAULT = Path("secrets.env.age")
IDENTITY = Path("key.txt")
SAMPLE_ENV = {
    "DATABASE_URL": "postgres://localhost/db",
    "SECRET_KEY": "supersecret",
    "DEBUG": "false",
    "API_KEY": "abc123",
}


def _patch_decrypt(env=None):
    return patch("envcrypt.search.decrypt_env_file", return_value=env or SAMPLE_ENV)


def test_search_vault_key_glob_match():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, "*KEY*")
    keys = {m.key for m in result.matches}
    assert "SECRET_KEY" in keys
    assert "API_KEY" in keys
    assert "DATABASE_URL" not in keys
    assert result.searched_files == 1


def test_search_vault_exact_key_match():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, "DEBUG")
    assert result.total == 1
    assert result.matches[0].key == "DEBUG"


def test_search_vault_no_match_returns_empty():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, "NONEXISTENT")
    assert result.total == 0


def test_search_vault_values_flag():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, "*postgres*", search_values=True)
    assert result.total == 1
    assert result.matches[0].key == "DATABASE_URL"


def test_search_vault_case_insensitive_default():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, "*key*")
    keys = {m.key for m in result.matches}
    assert "SECRET_KEY" in keys
    assert "API_KEY" in keys


def test_search_vault_case_sensitive_no_match():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, "*key*", case_sensitive=True)
    assert result.total == 0


def test_search_vault_regex_mode():
    with _patch_decrypt():
        result = search_vault(VAULT, IDENTITY, r"^(SECRET|API)_KEY$", use_regex=True)
    keys = {m.key for m in result.matches}
    assert keys == {"SECRET_KEY", "API_KEY"}


def test_search_vault_decrypt_failure_raises():
    with patch("envcrypt.search.decrypt_env_file", side_effect=RuntimeError("bad")):
        with pytest.raises(SearchError, match="Failed to decrypt"):
            search_vault(VAULT, IDENTITY, "*")


def test_search_vaults_aggregates_results():
    vault_a = Path("a.env.age")
    vault_b = Path("b.env.age")

    def fake_decrypt(vault_file, identity_file):
        if vault_file == vault_a:
            return {"ALPHA": "1"}
        return {"BETA": "2"}

    with patch("envcrypt.search.decrypt_env_file", side_effect=fake_decrypt):
        result = search_vaults([vault_a, vault_b], IDENTITY, "*")

    assert result.searched_files == 2
    assert result.total == 2
    sources = {m.vault_file for m in result.matches}
    assert sources == {vault_a, vault_b}


def test_search_match_str():
    m = SearchMatch(key="FOO", value="bar", vault_file=Path("x.age"))
    assert str(m) == "x.age::FOO=bar"
