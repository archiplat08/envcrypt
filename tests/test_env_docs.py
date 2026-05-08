"""Tests for envcrypt.env_docs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from envcrypt.env_docs import (
    DocsError,
    _docs_path,
    get_doc,
    load_docs,
    remove_doc,
    save_docs,
    set_doc,
)
from envcrypt.cli_docs import docs


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"dummy")
    return p


# --- unit tests ---

def test_load_docs_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_docs(vault_file) == {}


def test_docs_file_placed_next_to_vault(vault_file: Path) -> None:
    assert _docs_path(vault_file) == vault_file.with_suffix(".docs.json")


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    data = {"DB_PASSWORD": "Database password", "API_KEY": "Third-party API key"}
    save_docs(vault_file, data)
    assert load_docs(vault_file) == data


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _docs_path(vault_file).write_text("not json", encoding="utf-8")
    with pytest.raises(DocsError, match="Corrupt"):
        load_docs(vault_file)


def test_set_doc_creates_entry(vault_file: Path) -> None:
    set_doc(vault_file, "SECRET", "A very secret value")
    assert load_docs(vault_file)["SECRET"] == "A very secret value"


def test_set_doc_updates_existing_entry(vault_file: Path) -> None:
    set_doc(vault_file, "SECRET", "old")
    set_doc(vault_file, "SECRET", "new")
    assert load_docs(vault_file)["SECRET"] == "new"


def test_set_doc_empty_key_raises(vault_file: Path) -> None:
    with pytest.raises(DocsError, match="empty"):
        set_doc(vault_file, "  ", "some doc")


def test_remove_doc_returns_true_when_removed(vault_file: Path) -> None:
    set_doc(vault_file, "KEY", "desc")
    assert remove_doc(vault_file, "KEY") is True
    assert "KEY" not in load_docs(vault_file)


def test_remove_doc_returns_false_when_not_found(vault_file: Path) -> None:
    assert remove_doc(vault_file, "MISSING") is False


def test_get_doc_returns_value(vault_file: Path) -> None:
    set_doc(vault_file, "TOKEN", "Auth token")
    assert get_doc(vault_file, "TOKEN") == "Auth token"


def test_get_doc_returns_none_when_absent(vault_file: Path) -> None:
    assert get_doc(vault_file, "NOPE") is None


# --- CLI tests ---

@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_cli_set_and_list(vault_file: Path, runner: CliRunner) -> None:
    result = runner.invoke(docs, ["set", str(vault_file), "DB_URL", "Database URL"])
    assert result.exit_code == 0
    assert "Documented 'DB_URL'" in result.output

    result = runner.invoke(docs, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "DB_URL: Database URL" in result.output


def test_cli_get_existing_key(vault_file: Path, runner: CliRunner) -> None:
    set_doc(vault_file, "MY_KEY", "My documentation")
    result = runner.invoke(docs, ["get", str(vault_file), "MY_KEY"])
    assert result.exit_code == 0
    assert "My documentation" in result.output


def test_cli_get_missing_key(vault_file: Path, runner: CliRunner) -> None:
    result = runner.invoke(docs, ["get", str(vault_file), "GHOST"])
    assert result.exit_code == 0
    assert "No documentation found" in result.output


def test_cli_remove_existing_key(vault_file: Path, runner: CliRunner) -> None:
    set_doc(vault_file, "OLD", "old doc")
    result = runner.invoke(docs, ["remove", str(vault_file), "OLD"])
    assert result.exit_code == 0
    assert "Removed documentation" in result.output


def test_cli_list_empty(vault_file: Path, runner: CliRunner) -> None:
    result = runner.invoke(docs, ["list", str(vault_file)])
    assert result.exit_code == 0
    assert "No documentation entries found" in result.output
