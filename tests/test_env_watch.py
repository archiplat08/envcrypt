"""Tests for envcrypt.env_watch."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_watch import WatchError, WatchEvent, watch_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"initial content")
    return p


def test_watch_fires_on_first_seen(vault_file: Path) -> None:
    events: list[WatchEvent] = []

    with patch("time.sleep"):
        watch_vault(vault_file, events.append, interval=0.0, max_events=1)

    assert len(events) == 1
    assert events[0].is_first_seen
    assert events[0].old_hash is None
    assert events[0].vault == vault_file


def test_watch_fires_on_content_change(vault_file: Path) -> None:
    events: list[WatchEvent] = []
    call_count = 0

    original_sleep = time.sleep

    def _fake_sleep(secs: float) -> None:  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            vault_file.write_bytes(b"changed content")

    with patch("time.sleep", side_effect=_fake_sleep):
        watch_vault(vault_file, events.append, interval=0.0, max_events=2)

    assert len(events) == 2
    assert not events[1].is_first_seen
    assert events[1].old_hash != events[1].new_hash


def test_watch_missing_vault_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope.age"
    with pytest.raises(WatchError, match="Vault not found"):
        watch_vault(missing, lambda e: None)


def test_watch_event_hash_is_consistent(vault_file: Path) -> None:
    events: list[WatchEvent] = []

    with patch("time.sleep"):
        watch_vault(vault_file, events.append, interval=0.0, max_events=1)

    import hashlib
    expected = hashlib.sha256(vault_file.read_bytes()).hexdigest()
    assert events[0].new_hash == expected


def test_watch_no_duplicate_events_when_unchanged(vault_file: Path) -> None:
    """When content does not change, callback must not be called twice."""
    events: list[WatchEvent] = []
    call_count = 0

    def _fake_sleep(secs: float) -> None:  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        if call_count >= 3:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        with patch("time.sleep", side_effect=_fake_sleep):
            watch_vault(vault_file, events.append, interval=0.0)

    # Only the first-seen event should have fired.
    assert len(events) == 1
