"""Tests for envcrypt.merge and envcrypt.cli_merge."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envcrypt.merge import (
    ConflictStrategy,
    MergeError,
    MergeResult,
    merge_envs,
    merge_vault_files,
)
from envcrypt.cli_merge import merge


# ---------------------------------------------------------------------------
# merge_envs unit tests
# ---------------------------------------------------------------------------

def test_merge_envs_adds_new_keys():
    base = {"A": "1"}
    other = {"A": "1", "B": "2"}
    result = merge_envs(base, other)
    assert result.merged == {"A": "1", "B": "2"}
    assert result.added_keys == ["B"]
    assert result.conflicts == []


def test_merge_envs_ours_strategy_keeps_base_on_conflict():
    base = {"KEY": "base_val"}
    other = {"KEY": "other_val"}
    result = merge_envs(base, other, strategy=ConflictStrategy.OURS)
    assert result.merged["KEY"] == "base_val"
    assert "KEY" in result.conflicts


def test_merge_envs_theirs_strategy_uses_other_on_conflict():
    base = {"KEY": "base_val"}
    other = {"KEY": "other_val"}
    result = merge_envs(base, other, strategy=ConflictStrategy.THEIRS)
    assert result.merged["KEY"] == "other_val"
    assert "KEY" in result.conflicts


def test_merge_envs_error_strategy_raises_on_conflict():
    base = {"KEY": "v1"}
    other = {"KEY": "v2"}
    with pytest.raises(MergeError, match="Conflict on key 'KEY'"):
        merge_envs(base, other, strategy=ConflictStrategy.ERROR)


def test_merge_envs_no_conflict_identical_values():
    env = {"A": "1", "B": "2"}
    result = merge_envs(env, dict(env))
    assert result.conflicts == []
    assert result.added_keys == []


# ---------------------------------------------------------------------------
# merge_vault_files integration (fully mocked)
# ---------------------------------------------------------------------------

def test_merge_vault_files_success(tmp_path):
    base = tmp_path / "base.env.age"
    other = tmp_path / "other.env.age"
    identity = tmp_path / "key.txt"
    recipients_file = tmp_path / ".recipients"
    base.touch()
    other.touch()
    identity.touch()
    recipients_file.write_text("age1abc\n")

    with (
        patch("envcrypt.merge.decrypt") as mock_decrypt,
        patch("envcrypt.merge.encrypt") as mock_encrypt,
        patch("envcrypt.merge.load_recipients", return_value=["age1abc"]),
    ):
        mock_decrypt.side_effect = ["A=1\nB=2\n", "A=1\nC=3\n"]
        result = merge_vault_files(
            base, other, identity, recipients_file=recipients_file
        )

    assert "C" in result.added_keys
    assert result.conflicts == []
    mock_encrypt.assert_called_once()


def test_merge_vault_files_no_recipients_raises(tmp_path):
    base = tmp_path / "base.env.age"
    other = tmp_path / "other.env.age"
    identity = tmp_path / "key.txt"

    with (
        patch("envcrypt.merge.decrypt", return_value="A=1\n"),
        patch("envcrypt.merge.load_recipients", return_value=[]),
    ):
        with pytest.raises(MergeError, match="No recipients"):
            merge_vault_files(base, other, identity)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner():
    return CliRunner()


def test_cli_merge_success(runner, tmp_path):
    base = tmp_path / "base.env.age"
    other = tmp_path / "other.env.age"
    identity = tmp_path / "key.txt"
    base.touch()
    other.touch()
    identity.touch()

    mock_result = MergeResult(
        merged={"A": "1", "B": "2"},
        added_keys=["B"],
        conflicts=[],
    )
    with patch("envcrypt.cli_merge.merge_vault_files", return_value=mock_result):
        res = runner.invoke(
            merge,
            ["run", str(base), str(other), "--identity", str(identity)],
        )
    assert res.exit_code == 0
    assert "Added" in res.output


def test_cli_merge_error_propagates(runner, tmp_path):
    base = tmp_path / "base.env.age"
    other = tmp_path / "other.env.age"
    identity = tmp_path / "key.txt"
    base.touch()
    other.touch()
    identity.touch()

    with patch(
        "envcrypt.cli_merge.merge_vault_files",
        side_effect=MergeError("Conflict on key 'X'"),
    ):
        res = runner.invoke(
            merge,
            [
                "run", str(base), str(other),
                "--identity", str(identity),
                "--strategy", "error",
            ],
        )
    assert res.exit_code != 0
    assert "Conflict" in res.output
