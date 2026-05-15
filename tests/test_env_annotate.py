"""Tests for envcrypt.env_annotate."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_annotate import (
    AnnotateError,
    _annotations_path,
    get_annotation,
    load_annotations,
    remove_annotation,
    save_annotations,
    set_annotation,
)


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"dummy")
    return p


def test_load_annotations_returns_empty_when_no_file(vault_file: Path) -> None:
    assert load_annotations(vault_file) == {}


def test_annotations_file_placed_next_to_vault(vault_file: Path) -> None:
    expected = vault_file.with_suffix(".annotations.json")
    assert _annotations_path(vault_file) == expected


def test_save_and_load_roundtrip(vault_file: Path) -> None:
    data = {"DB_HOST": "Primary database host", "API_KEY": "Third-party API token"}
    save_annotations(vault_file, data)
    loaded = load_annotations(vault_file)
    assert loaded == data


def test_load_raises_on_corrupt_json(vault_file: Path) -> None:
    _annotations_path(vault_file).write_text("not-json", encoding="utf-8")
    with pytest.raises(AnnotateError, match="Corrupt"):
        load_annotations(vault_file)


def test_load_raises_when_root_is_not_object(vault_file: Path) -> None:
    _annotations_path(vault_file).write_text(json.dumps(["a", "b"]), encoding="utf-8")
    with pytest.raises(AnnotateError, match="JSON object"):
        load_annotations(vault_file)


def test_set_annotation_creates_entry(vault_file: Path) -> None:
    result = set_annotation(vault_file, "SECRET_KEY", "Django secret key")
    assert result["SECRET_KEY"] == "Django secret key"


def test_set_annotation_overwrites_existing(vault_file: Path) -> None:
    set_annotation(vault_file, "HOST", "old")
    result = set_annotation(vault_file, "HOST", "new")
    assert result["HOST"] == "new"
    assert len(result) == 1


def test_remove_annotation_deletes_key(vault_file: Path) -> None:
    set_annotation(vault_file, "A", "alpha")
    set_annotation(vault_file, "B", "beta")
    result = remove_annotation(vault_file, "A")
    assert "A" not in result
    assert result["B"] == "beta"


def test_remove_annotation_noop_when_absent(vault_file: Path) -> None:
    result = remove_annotation(vault_file, "MISSING")
    assert result == {}


def test_get_annotation_returns_text(vault_file: Path) -> None:
    set_annotation(vault_file, "TOKEN", "Auth token")
    assert get_annotation(vault_file, "TOKEN") == "Auth token"


def test_get_annotation_returns_none_when_absent(vault_file: Path) -> None:
    assert get_annotation(vault_file, "NOPE") is None
