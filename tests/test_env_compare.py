"""Tests for envcrypt.env_compare."""
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from envcrypt.env_compare import compare_vaults, CompareError, CompareResult


ENV_A = "KEY1=alpha\nKEY2=shared\nKEY3=only_in_a\n"
ENV_B = "KEY1=beta\nKEY2=shared\nKEY4=only_in_b\n"


@pytest.fixture()
def vault_a(tmp_path: Path) -> Path:
    p = tmp_path / "a.env.age"
    p.write_bytes(b"dummy")
    return p


@pytest.fixture()
def vault_b(tmp_path: Path) -> Path:
    p = tmp_path / "b.env.age"
    p.write_bytes(b"dummy")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-FAKE")
    return p


def _patch_decrypt(side_effect):
    return patch("envcrypt.env_compare.decrypt", side_effect=side_effect)


def test_compare_vaults_detects_changed_key(vault_a, vault_b, identity_file):
    calls = iter([ENV_A, ENV_B])
    with _patch_decrypt(lambda *_: next(calls)):
        result = compare_vaults(vault_a, vault_b, identity_file)

    changed = [e for e in result.entries if e.status == "changed"]
    assert any(e.key == "KEY1" for e in changed)


def test_compare_vaults_detects_added_and_removed(vault_a, vault_b, identity_file):
    calls = iter([ENV_A, ENV_B])
    with _patch_decrypt(lambda *_: next(calls)):
        result = compare_vaults(vault_a, vault_b, identity_file)

    keys = {e.key: e.status for e in result.entries}
    assert keys.get("KEY3") == "removed"
    assert keys.get("KEY4") == "added"


def test_compare_vaults_unchanged_hidden_by_default(vault_a, vault_b, identity_file):
    calls = iter([ENV_A, ENV_B])
    with _patch_decrypt(lambda *_: next(calls)):
        result = compare_vaults(vault_a, vault_b, identity_file)

    assert all(e.status != "unchanged" for e in result.entries)


def test_compare_vaults_unchanged_shown_when_requested(vault_a, vault_b, identity_file):
    calls = iter([ENV_A, ENV_B])
    with _patch_decrypt(lambda *_: next(calls)):
        result = compare_vaults(vault_a, vault_b, identity_file, show_unchanged=True)

    assert any(e.status == "unchanged" for e in result.entries)


def test_compare_vaults_no_differences_flag(vault_a, vault_b, identity_file):
    same = "KEY1=val\n"
    with _patch_decrypt(lambda *_: same):
        result = compare_vaults(vault_a, vault_b, identity_file)

    assert not result.has_differences


def test_compare_vaults_missing_vault_raises(tmp_path, identity_file):
    missing = tmp_path / "ghost.age"
    real = tmp_path / "real.age"
    real.write_bytes(b"x")
    with pytest.raises(CompareError, match="Vault not found"):
        compare_vaults(missing, real, identity_file)


def test_compare_vaults_decrypt_failure_raises(vault_a, vault_b, identity_file):
    with _patch_decrypt(side_effect=RuntimeError("bad key")):
        with pytest.raises(CompareError, match="Failed to decrypt"):
            compare_vaults(vault_a, vault_b, identity_file)


def test_compare_result_summary(vault_a, vault_b, identity_file):
    calls = iter([ENV_A, ENV_B])
    with _patch_decrypt(lambda *_: next(calls)):
        result = compare_vaults(vault_a, vault_b, identity_file)

    assert "+" in result.summary and "-" in result.summary
