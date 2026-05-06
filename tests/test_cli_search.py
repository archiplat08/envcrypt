"""Tests for envcrypt.cli_search CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_search import search
from envcrypt.search import SearchError, SearchMatch, SearchResult


@pytest.fixture()
def runner():
    return CliRunner()


def _make_result(*keys, vault=Path("secrets.env.age")):
    result = SearchResult(searched_files=1)
    for key in keys:
        result.matches.append(SearchMatch(key=key, value="val", vault_file=vault))
    return result


def test_find_prints_matches(runner, tmp_path):
    vault = tmp_path / "secrets.env.age"
    vault.touch()
    identity = tmp_path / "key.txt"
    identity.touch()

    with patch("envcrypt.cli_search.search_vaults", return_value=_make_result("API_KEY")) as mock:
        result = runner.invoke(
            search,
            ["find", "*KEY*", "--vault", str(vault), "--identity", str(identity)],
        )

    assert result.exit_code == 0
    assert "API_KEY" in result.output
    assert "1 match" in result.output


def test_find_no_matches_message(runner, tmp_path):
    vault = tmp_path / "secrets.env.age"
    vault.touch()
    identity = tmp_path / "key.txt"
    identity.touch()

    empty = SearchResult(searched_files=1)
    with patch("envcrypt.cli_search.search_vaults", return_value=empty):
        result = runner.invoke(
            search,
            ["find", "NOTHING", "--vault", str(vault), "--identity", str(identity)],
        )

    assert result.exit_code == 0
    assert "No matches" in result.output


def test_find_search_error_exits_nonzero(runner, tmp_path):
    vault = tmp_path / "secrets.env.age"
    vault.touch()
    identity = tmp_path / "key.txt"
    identity.touch()

    with patch("envcrypt.cli_search.search_vaults", side_effect=SearchError("decrypt failed")):
        result = runner.invoke(
            search,
            ["find", "*", "--vault", str(vault), "--identity", str(identity)],
        )

    assert result.exit_code != 0
    assert "decrypt failed" in result.output


def test_find_passes_flags(runner, tmp_path):
    vault = tmp_path / "secrets.env.age"
    vault.touch()
    identity = tmp_path / "key.txt"
    identity.touch()

    with patch("envcrypt.cli_search.search_vaults", return_value=SearchResult(searched_files=1)) as mock:
        runner.invoke(
            search,
            [
                "find", "*KEY*",
                "--vault", str(vault),
                "--identity", str(identity),
                "--values",
                "--case-sensitive",
                "--regex",
            ],
        )
        _, kwargs = mock.call_args
        assert kwargs["search_values"] is True
        assert kwargs["case_sensitive"] is True
        assert kwargs["use_regex"] is True
