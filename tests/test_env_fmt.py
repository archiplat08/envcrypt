"""Tests for envcrypt.env_fmt."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_fmt import FmtError, format_env, format_vault, _normalize_value


# ---------------------------------------------------------------------------
# _normalize_value
# ---------------------------------------------------------------------------

def test_normalize_value_strips_double_quotes():
    assert _normalize_value('"hello"') == "hello"


def test_normalize_value_strips_single_quotes():
    assert _normalize_value("'world'") == "world"


def test_normalize_value_leaves_plain_value():
    assert _normalize_value("plain") == "plain"


def test_normalize_value_leaves_single_char():
    assert _normalize_value('"') == '"'


# ---------------------------------------------------------------------------
# format_env
# ---------------------------------------------------------------------------

def test_format_env_sorts_keys():
    env = {"ZEBRA": "1", "ALPHA": "2", "MIDDLE": "3"}
    result = format_env(env, sort_keys=True, normalize_quotes=False)
    assert list(result.keys()) == ["ALPHA", "MIDDLE", "ZEBRA"]


def test_format_env_no_sort_preserves_order():
    env = {"ZEBRA": "1", "ALPHA": "2"}
    result = format_env(env, sort_keys=False, normalize_quotes=False)
    assert list(result.keys()) == ["ZEBRA", "ALPHA"]


def test_format_env_normalizes_quotes():
    env = {"KEY": '"value"'}
    result = format_env(env, sort_keys=False, normalize_quotes=True)
    assert result["KEY"] == "value"


def test_format_env_no_normalize_keeps_quotes():
    env = {"KEY": '"value"'}
    result = format_env(env, sort_keys=False, normalize_quotes=False)
    assert result["KEY"] == '"value"'


# ---------------------------------------------------------------------------
# format_vault
# ---------------------------------------------------------------------------

_PLAIN_ENV = "BETA=2\nALPHA=1\n"
_SORTED_ENV = "ALPHA=1\nBETA=2\n"


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "test.env.age"
    p.write_bytes(b"fake-encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-FAKE")
    return p


def _patch_fmt(decrypt_return: str):
    return patch("envcrypt.env_fmt.decrypt", return_value=decrypt_return)


def test_format_vault_detects_change(vault_file, identity_file, tmp_path):
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with _patch_fmt(_PLAIN_ENV), \
         patch("envcrypt.env_fmt.encrypt_env_file") as mock_enc:
        result = format_vault(vault_file, identity_file, recipients)

    assert result.changed is True
    mock_enc.assert_called_once()


def test_format_vault_no_change_when_already_sorted(vault_file, identity_file, tmp_path):
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with _patch_fmt(_SORTED_ENV), \
         patch("envcrypt.env_fmt.encrypt_env_file") as mock_enc:
        result = format_vault(vault_file, identity_file, recipients)

    assert result.changed is False
    mock_enc.assert_not_called()


def test_format_vault_dry_run_does_not_encrypt(vault_file, identity_file, tmp_path):
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with _patch_fmt(_PLAIN_ENV), \
         patch("envcrypt.env_fmt.encrypt_env_file") as mock_enc:
        result = format_vault(vault_file, identity_file, recipients, dry_run=True)

    assert result.changed is True
    mock_enc.assert_not_called()


def test_format_vault_missing_file_raises(tmp_path, identity_file):
    missing = tmp_path / "nope.env.age"
    recipients = tmp_path / ".recipients"
    with pytest.raises(FmtError, match="not found"):
        format_vault(missing, identity_file, recipients)


def test_fmt_result_summary_no_change(vault_file, identity_file, tmp_path):
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1fake")

    with _patch_fmt(_SORTED_ENV), patch("envcrypt.env_fmt.encrypt_env_file"):
        result = format_vault(vault_file, identity_file, recipients)

    assert "no changes" in result.summary()
