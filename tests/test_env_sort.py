"""Tests for envcrypt.env_sort."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_sort import SortError, SortResult, sort_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_text("encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(vault_file: Path, env_text: str, recipients: list):
    """Return context managers that mock decrypt, encrypt, and load_recipients."""
    return (
        patch("envcrypt.env_sort.decrypt", return_value=env_text),
        patch("envcrypt.env_sort.encrypt"),
        patch("envcrypt.env_sort.load_recipients", return_value=recipients),
    )


def test_sort_vault_success(vault_file, identity_file):
    env_text = "ZEBRA=1\nAPPLE=2\nMIDDLE=3\n"
    p1, p2, p3 = _patch_crypto(vault_file, env_text, ["age1abc"])
    with p1, p2 as mock_enc, p3:
        result = sort_vault(vault_file, identity_file)

    assert result.changed is True
    assert result.sorted_order == ["APPLE", "MIDDLE", "ZEBRA"]
    mock_enc.assert_called_once()


def test_sort_vault_already_sorted(vault_file, identity_file):
    env_text = "ALPHA=1\nBETA=2\nGAMMA=3\n"
    p1, p2, p3 = _patch_crypto(vault_file, env_text, ["age1abc"])
    with p1, p2 as mock_enc, p3:
        result = sort_vault(vault_file, identity_file)

    assert result.changed is False
    mock_enc.assert_not_called()


def test_sort_vault_reverse(vault_file, identity_file):
    env_text = "ALPHA=1\nBETA=2\nGAMMA=3\n"
    p1, p2, p3 = _patch_crypto(vault_file, env_text, ["age1abc"])
    with p1, p2, p3:
        result = sort_vault(vault_file, identity_file, reverse=True)

    assert result.sorted_order == ["GAMMA", "BETA", "ALPHA"]
    assert result.changed is True


def test_sort_vault_group_by_prefix(vault_file, identity_file):
    env_text = "DB_PORT=5432\nAPP_NAME=myapp\nDB_HOST=localhost\nAPP_ENV=prod\n"
    p1, p2, p3 = _patch_crypto(vault_file, env_text, ["age1abc"])
    with p1, p2, p3:
        result = sort_vault(vault_file, identity_file, group_by_prefix=True)

    assert result.sorted_order.index("APP_ENV") < result.sorted_order.index("DB_HOST")
    assert result.sorted_order.index("APP_ENV") < result.sorted_order.index("APP_NAME") or \
           result.sorted_order.index("APP_NAME") < result.sorted_order.index("DB_HOST")


def test_sort_vault_missing_vault_raises(tmp_path, identity_file):
    missing = tmp_path / "ghost.age"
    with pytest.raises(SortError, match="Vault not found"):
        sort_vault(missing, identity_file)


def test_sort_vault_no_recipients_raises(vault_file, identity_file):
    p1, p2, p3 = _patch_crypto(vault_file, "KEY=val\n", [])
    with p1, p2, p3:
        with pytest.raises(SortError, match="No recipients"):
            sort_vault(vault_file, identity_file)


def test_sort_result_summary_changed():
    r = SortResult(original_order=["B", "A"], sorted_order=["A", "B"], changed=True)
    assert "Sorted 2" in r.summary()


def test_sort_result_summary_unchanged():
    r = SortResult(original_order=["A", "B"], sorted_order=["A", "B"], changed=False)
    assert "already in sorted order" in r.summary()


def test_sort_vault_custom_output(vault_file, identity_file, tmp_path):
    env_text = "Z=1\nA=2\n"
    out = tmp_path / "sorted.age"
    p1, p2, p3 = _patch_crypto(vault_file, env_text, ["age1abc"])
    with p1, p2 as mock_enc, p3:
        sort_vault(vault_file, identity_file, output=out)

    args, _ = mock_enc.call_args
    assert args[1] == out
