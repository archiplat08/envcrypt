"""Tests for envcrypt.diff module."""

import pytest

from envcrypt.diff import DiffEntry, diff_envs, diff_env_files, format_diff


# ---------------------------------------------------------------------------
# diff_envs
# ---------------------------------------------------------------------------

def test_diff_envs_added():
    entries = diff_envs({}, {"FOO": "bar"})
    assert len(entries) == 1
    assert entries[0].status == "added"
    assert entries[0].key == "FOO"
    assert entries[0].new_value == "bar"
    assert entries[0].old_value is None


def test_diff_envs_removed():
    entries = diff_envs({"FOO": "bar"}, {})
    assert len(entries) == 1
    assert entries[0].status == "removed"
    assert entries[0].old_value == "bar"


def test_diff_envs_changed():
    entries = diff_envs({"FOO": "old"}, {"FOO": "new"})
    assert len(entries) == 1
    e = entries[0]
    assert e.status == "changed"
    assert e.old_value == "old"
    assert e.new_value == "new"


def test_diff_envs_unchanged_hidden_by_default():
    entries = diff_envs({"FOO": "bar"}, {"FOO": "bar"})
    assert entries == []


def test_diff_envs_unchanged_shown_when_requested():
    entries = diff_envs({"FOO": "bar"}, {"FOO": "bar"}, show_unchanged=True)
    assert len(entries) == 1
    assert entries[0].status == "unchanged"


def test_diff_envs_sorted_keys():
    old = {"Z": "1", "A": "2"}
    new = {"Z": "1", "A": "changed"}
    entries = diff_envs(old, new)
    assert entries[0].key == "A"


def test_diff_envs_mixed():
    old = {"A": "1", "B": "2", "C": "3"}
    new = {"A": "1", "B": "99", "D": "4"}
    entries = diff_envs(old, new)
    statuses = {e.key: e.status for e in entries}
    assert statuses["B"] == "changed"
    assert statuses["C"] == "removed"
    assert statuses["D"] == "added"
    assert "A" not in statuses


# ---------------------------------------------------------------------------
# diff_env_files
# ---------------------------------------------------------------------------

def test_diff_env_files(tmp_path):
    old_file = tmp_path / "old.env"
    new_file = tmp_path / "new.env"
    old_file.write_text("FOO=1\nBAR=2\n")
    new_file.write_text("FOO=1\nBAR=99\nBAZ=3\n")

    entries = diff_env_files(str(old_file), str(new_file))
    statuses = {e.key: e.status for e in entries}
    assert statuses["BAR"] == "changed"
    assert statuses["BAZ"] == "added"
    assert "FOO" not in statuses


# ---------------------------------------------------------------------------
# format_diff
# ---------------------------------------------------------------------------

def test_format_diff_masks_values_by_default():
    entries = [
        DiffEntry(key="SECRET", status="added", new_value="s3cr3t"),
        DiffEntry(key="OLD", status="removed", old_value="gone"),
    ]
    output = format_diff(entries)
    assert "s3cr3t" not in output
    assert "gone" not in output
    assert "+ SECRET=***" in output
    assert "- OLD=***" in output


def test_format_diff_shows_values_when_unmasked():
    entries = [
        DiffEntry(key="KEY", status="changed", old_value="v1", new_value="v2"),
    ]
    output = format_diff(entries, mask_values=False)
    assert "v1" in output
    assert "v2" in output
    assert "~" in output


def test_format_diff_empty():
    assert format_diff([]) == ""
