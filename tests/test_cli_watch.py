"""Tests for envcrypt.cli_watch."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_watch import watch
from envcrypt.env_watch import WatchError, WatchEvent


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"data")
    return p


def _make_event(vault: Path, *, first: bool = True) -> WatchEvent:
    return WatchEvent(
        vault=vault,
        old_hash=None if first else "aabbcc",
        new_hash="ddeeff",
    )


def test_start_cmd_prints_initial_message(runner: CliRunner, vault_file: Path) -> None:
    def _fake_watch(path, cb, *, interval, max_events=None):
        cb(_make_event(path, first=True))

    with patch("envcrypt.cli_watch.watch_vault", side_effect=_fake_watch):
        result = runner.invoke(watch, ["start", str(vault_file)])

    assert result.exit_code == 0
    assert "Watching" in result.output
    assert "Initial snapshot" in result.output


def test_start_cmd_quiet_suppresses_header(runner: CliRunner, vault_file: Path) -> None:
    def _fake_watch(path, cb, *, interval, max_events=None):
        cb(_make_event(path, first=True))

    with patch("envcrypt.cli_watch.watch_vault", side_effect=_fake_watch):
        result = runner.invoke(watch, ["start", str(vault_file), "--quiet"])

    assert result.exit_code == 0
    assert "Watching" not in result.output


def test_start_cmd_change_event_message(runner: CliRunner, vault_file: Path) -> None:
    def _fake_watch(path, cb, *, interval, max_events=None):
        cb(_make_event(path, first=False))

    with patch("envcrypt.cli_watch.watch_vault", side_effect=_fake_watch):
        result = runner.invoke(watch, ["start", str(vault_file), "--quiet"])

    assert "Change detected" in result.output


def test_start_cmd_watch_error_exits_nonzero(runner: CliRunner, vault_file: Path) -> None:
    with patch(
        "envcrypt.cli_watch.watch_vault",
        side_effect=WatchError("boom"),
    ):
        result = runner.invoke(watch, ["start", str(vault_file)])

    assert result.exit_code != 0
    assert "boom" in result.output
