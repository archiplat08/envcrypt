"""Tests for envcrypt.cli_rename."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from envcrypt.cli_rename import rename
from envcrypt.env_rename import RenameError, RenameResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / ".env.age"
    p.write_bytes(b"encrypted")
    return p


def test_rename_key_cmd_success(runner, vault_file, tmp_path, monkeypatch):
    identity = tmp_path / "id.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")

    fake_result = RenameResult(
        old_key="OLD",
        new_key="NEW",
        vault=vault_file,
        aliased=False,
    )
    monkeypatch.setattr(
        "envcrypt.cli_rename.rename_key", lambda **_kw: fake_result
    )

    result = runner.invoke(
        rename,
        ["key", "OLD", "NEW", "--vault", str(vault_file), "--identity", str(identity)],
    )
    assert result.exit_code == 0
    assert "OLD" in result.output
    assert "NEW" in result.output


def test_rename_key_cmd_with_alias(runner, vault_file, tmp_path, monkeypatch):
    identity = tmp_path / "id.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")

    fake_result = RenameResult(
        old_key="OLD",
        new_key="NEW",
        vault=vault_file,
        aliased=True,
    )
    monkeypatch.setattr(
        "envcrypt.cli_rename.rename_key", lambda **_kw: fake_result
    )

    result = runner.invoke(
        rename,
        [
            "key", "OLD", "NEW",
            "--vault", str(vault_file),
            "--identity", str(identity),
            "--keep-alias",
        ],
    )
    assert result.exit_code == 0
    assert "alias kept" in result.output


def test_rename_key_cmd_error_exits_nonzero(runner, vault_file, tmp_path, monkeypatch):
    identity = tmp_path / "id.txt"
    identity.write_text("AGE-SECRET-KEY-FAKE")

    monkeypatch.setattr(
        "envcrypt.cli_rename.rename_key",
        lambda **_kw: (_ for _ in ()).throw(RenameError("Key not found")),
    )

    result = runner.invoke(
        rename,
        ["key", "GHOST", "NEW", "--vault", str(vault_file), "--identity", str(identity)],
    )
    assert result.exit_code != 0
    assert "Key not found" in result.output
