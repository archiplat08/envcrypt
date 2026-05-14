"""Tests for envcrypt.env_prune."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from envcrypt.env_prune import PruneError, PruneResult, prune_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-...")
    return p


def _patch_crypto(vault_file: Path, plaintext: str, recipients: list[str]):
    """Return a context manager that patches decrypt/encrypt/load_recipients."""
    return patch.multiple(
        "envcrypt.env_prune",
        decrypt=MagicMock(return_value=plaintext),
        encrypt=MagicMock(),
        load_recipients=MagicMock(return_value=recipients),
    )


def test_prune_vault_removes_unlisted_keys(vault_file, identity_file):
    plaintext = "FOO=1\nBAR=2\nBAZ=3\n"
    with _patch_crypto(vault_file, plaintext, ["age1abc"]):
        result = prune_vault(vault_file, identity_file, keep_keys=["FOO", "BAZ"])

    assert result.removed == ["BAR"]
    assert set(result.kept) == {"FOO", "BAZ"}
    assert result.count == 1


def test_prune_vault_nothing_to_remove(vault_file, identity_file):
    plaintext = "FOO=1\nBAR=2\n"
    with _patch_crypto(vault_file, plaintext, ["age1abc"]):
        result = prune_vault(vault_file, identity_file, keep_keys=["FOO", "BAR"])

    assert result.removed == []
    assert result.count == 0


def test_prune_vault_no_recipients_raises(vault_file, identity_file):
    plaintext = "FOO=1\nBAR=2\n"
    with _patch_crypto(vault_file, plaintext, []):
        with pytest.raises(PruneError, match="No recipients"):
            prune_vault(vault_file, identity_file, keep_keys=["FOO"])


def test_prune_vault_missing_vault_raises(tmp_path, identity_file):
    missing = tmp_path / "ghost.env.age"
    with pytest.raises(PruneError, match="Vault not found"):
        prune_vault(missing, identity_file, keep_keys=["FOO"])


def test_prune_vault_custom_output(vault_file, identity_file, tmp_path):
    plaintext = "FOO=1\nBAR=2\n"
    out = tmp_path / "pruned.env.age"
    mock_encrypt = MagicMock()
    with patch.multiple(
        "envcrypt.env_prune",
        decrypt=MagicMock(return_value=plaintext),
        encrypt=mock_encrypt,
        load_recipients=MagicMock(return_value=["age1abc"]),
    ):
        prune_vault(vault_file, identity_file, keep_keys=["FOO"], output_path=out)

    args = mock_encrypt.call_args
    assert args[0][1] == out


def test_prune_result_summary_with_removals():
    r = PruneResult(removed=["OLD_KEY", "DEAD_VAR"], kept=["LIVE"])
    summary = r.summary()
    assert "2" in summary
    assert "OLD_KEY" in summary


def test_prune_result_summary_no_removals():
    r = PruneResult(removed=[], kept=["A", "B"])
    assert r.summary() == "No keys pruned."
