"""Tests for envcrypt.env_copy."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_copy import CopyError, CopyResult, copy_keys


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "vault.env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-...")
    return p


def _patch_copy(src_env: dict, dst_env: dict):
    """Return a context-manager stack that mocks crypto and recipients."""
    import contextlib
    from envcrypt.dotenv import serialize_dotenv

    @contextlib.contextmanager
    def _ctx():
        with patch("envcrypt.env_copy.load_recipients", return_value=["age1abc"]), \
             patch("envcrypt.env_copy.decrypt", side_effect=[
                 serialize_dotenv(src_env),
                 serialize_dotenv(dst_env),
             ]), \
             patch("envcrypt.env_copy.encrypt") as mock_enc:
            yield mock_enc

    return _ctx()


def test_copy_keys_all(vault_file: Path, identity_file: Path, tmp_path: Path):
    dst = tmp_path / "dst.env.age"
    dst.write_bytes(b"encrypted")

    src_env = {"KEY_A": "alpha", "KEY_B": "beta"}
    dst_env = {}

    with _patch_copy(src_env, dst_env) as mock_enc:
        result = copy_keys(vault_file, dst, identity_file)

    assert set(result.copied) == {"KEY_A", "KEY_B"}
    assert result.skipped == []
    mock_enc.assert_called_once()


def test_copy_keys_subset(vault_file: Path, identity_file: Path, tmp_path: Path):
    dst = tmp_path / "dst.env.age"
    dst.write_bytes(b"encrypted")

    src_env = {"KEY_A": "alpha", "KEY_B": "beta", "KEY_C": "gamma"}
    dst_env = {}

    with _patch_copy(src_env, dst_env):
        result = copy_keys(vault_file, dst, identity_file, keys=["KEY_A", "KEY_C"])

    assert result.copied == ["KEY_A", "KEY_C"]
    assert result.skipped == []


def test_copy_keys_skip_existing(vault_file: Path, identity_file: Path, tmp_path: Path):
    dst = tmp_path / "dst.env.age"
    dst.write_bytes(b"encrypted")

    src_env = {"KEY_A": "new_value"}
    dst_env = {"KEY_A": "old_value"}

    with _patch_copy(src_env, dst_env):
        result = copy_keys(vault_file, dst, identity_file, overwrite=False)

    assert result.copied == []
    assert result.skipped == ["KEY_A"]


def test_copy_keys_overwrite_existing(vault_file: Path, identity_file: Path, tmp_path: Path):
    dst = tmp_path / "dst.env.age"
    dst.write_bytes(b"encrypted")

    src_env = {"KEY_A": "new_value"}
    dst_env = {"KEY_A": "old_value"}

    with _patch_copy(src_env, dst_env):
        result = copy_keys(vault_file, dst, identity_file, overwrite=True)

    assert result.copied == ["KEY_A"]
    assert result.skipped == []


def test_copy_keys_missing_src_raises(identity_file: Path, tmp_path: Path):
    dst = tmp_path / "dst.env.age"
    dst.write_bytes(b"encrypted")
    missing = tmp_path / "nope.env.age"

    with pytest.raises(CopyError, match="Source vault not found"):
        copy_keys(missing, dst, identity_file)


def test_copy_keys_missing_dst_raises(vault_file: Path, identity_file: Path, tmp_path: Path):
    missing_dst = tmp_path / "nope_dst.env.age"

    with pytest.raises(CopyError, match="Destination vault not found"):
        copy_keys(vault_file, missing_dst, identity_file)


def test_copy_keys_no_recipients_raises(vault_file: Path, identity_file: Path, tmp_path: Path):
    dst = tmp_path / "dst.env.age"
    dst.write_bytes(b"encrypted")

    with patch("envcrypt.env_copy.load_recipients", return_value=[]):
        with pytest.raises(CopyError, match="No recipients"):
            copy_keys(vault_file, dst, identity_file)


def test_copy_result_summary():
    r = CopyResult(copied=["A", "B"], skipped=["C"])
    assert "2" in r.summary
    assert "1" in r.summary
