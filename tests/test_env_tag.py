"""Tests for envcrypt.env_tag."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_tag import (
    TagError,
    filter_keys_by_tag,
    load_tags,
    save_tags,
    tag_key,
    untag_key,
    _tags_path,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_text("")
    return p


def test_load_tags_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_tags(vault_file) == {}


def test_save_and_load_tags_roundtrip(vault_file: Path) -> None:
    data = {"DB_PASS": ["prod"], "API_KEY": ["dev", "staging"]}
    save_tags(vault_file, data)
    assert load_tags(vault_file) == data


def test_tags_file_is_placed_next_to_vault(vault_file: Path) -> None:
    save_tags(vault_file, {"X": ["dev"]})
    expected = vault_file.with_name(vault_file.name + ".tags.json")
    assert expected.exists()


def test_load_tags_raises_on_corrupt_json(vault_file: Path) -> None:
    _tags_path(vault_file).write_text("not-json")
    with pytest.raises(TagError, match="Corrupt"):
        load_tags(vault_file)


def test_load_tags_raises_when_root_is_not_object(vault_file: Path) -> None:
    _tags_path(vault_file).write_text(json.dumps(["a", "b"]))
    with pytest.raises(TagError, match="must contain a JSON object"):
        load_tags(vault_file)


def test_tag_key_adds_tag(vault_file: Path) -> None:
    tag_key(vault_file, "DB_PASS", "prod")
    assert "prod" in load_tags(vault_file)["DB_PASS"]


def test_tag_key_does_not_duplicate(vault_file: Path) -> None:
    tag_key(vault_file, "DB_PASS", "prod")
    tag_key(vault_file, "DB_PASS", "prod")
    assert load_tags(vault_file)["DB_PASS"].count("prod") == 1


def test_untag_key_removes_tag(vault_file: Path) -> None:
    tag_key(vault_file, "DB_PASS", "prod")
    untag_key(vault_file, "DB_PASS", "prod")
    assert "DB_PASS" not in load_tags(vault_file)


def test_untag_key_ignores_missing_tag(vault_file: Path) -> None:
    """Should not raise when the tag was never added."""
    untag_key(vault_file, "NONEXISTENT", "dev")
    assert load_tags(vault_file) == {}


def test_filter_keys_by_tag_returns_matching(vault_file: Path) -> None:
    tag_key(vault_file, "DB_PASS", "prod")
    tag_key(vault_file, "API_KEY", "dev")
    env = {"DB_PASS": "secret", "API_KEY": "key123", "LOG_LEVEL": "info"}
    result = filter_keys_by_tag(vault_file, env, "prod")
    assert result == {"DB_PASS": "secret"}


def test_filter_keys_by_tag_untagged_flag(vault_file: Path) -> None:
    tag_key(vault_file, "DB_PASS", "prod")
    env = {"DB_PASS": "secret", "LOG_LEVEL": "info"}
    result = filter_keys_by_tag(vault_file, env, "prod", untagged=True)
    assert result == {"LOG_LEVEL": "info"}
