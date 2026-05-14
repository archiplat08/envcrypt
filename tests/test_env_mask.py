"""Tests for envcrypt.env_mask."""
from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_mask import (
    MaskError,
    MaskResult,
    _mask_value,
    mask_env,
    mask_vault,
)


# ---------------------------------------------------------------------------
# _mask_value
# ---------------------------------------------------------------------------

def test_mask_value_returns_stars():
    assert _mask_value("supersecret") == "********"


def test_mask_value_empty_returns_stars():
    assert _mask_value("") == "********"


def test_mask_value_partial_reveals_prefix():
    result = _mask_value("supersecret", partial=True)
    assert result.startswith("supe")
    assert "*" in result


def test_mask_value_partial_short_value_fully_masked():
    # value shorter than or equal to _PARTIAL_VISIBLE → fully masked
    result = _mask_value("abc", partial=True)
    assert result == "********"


# ---------------------------------------------------------------------------
# mask_env
# ---------------------------------------------------------------------------

def test_mask_env_sensitive_key_is_masked():
    env = {"DATABASE_PASSWORD": "s3cr3t", "APP_NAME": "myapp"}
    result = mask_env(env)
    assert result.masked_count == 1
    masked = result.as_dict()
    assert masked["DATABASE_PASSWORD"] == "********"
    assert masked["APP_NAME"] == "myapp"


def test_mask_env_token_key_is_masked():
    env = {"GITHUB_TOKEN": "ghp_abc123", "PORT": "8080"}
    result = mask_env(env)
    assert result.masked_count == 1
    assert result.as_dict()["GITHUB_TOKEN"] == "********"


def test_mask_env_no_sensitive_keys():
    env = {"HOST": "localhost", "PORT": "5432"}
    result = mask_env(env)
    assert result.masked_count == 0
    assert result.as_dict() == env


def test_mask_env_extra_patterns():
    env = {"MY_CUSTOM_SECRET_FIELD": "value", "OTHER": "plain"}
    result = mask_env(env, extra_patterns=["*CUSTOM*"])
    assert result.as_dict()["MY_CUSTOM_SECRET_FIELD"] == "********"
    assert result.as_dict()["OTHER"] == "plain"


def test_mask_env_partial_mode():
    env = {"API_KEY": "longapikey123"}
    result = mask_env(env, partial=True)
    masked_value = result.as_dict()["API_KEY"]
    assert masked_value.startswith("long")
    assert masked_value != "longapikey123"


def test_mask_result_summary():
    env = {"SECRET_KEY": "abc", "HOST": "localhost"}
    result = mask_env(env)
    assert "1/2" in result.summary()


def test_mask_result_entries_order_preserved():
    env = {"Z_KEY": "z", "A_PASSWORD": "a", "M_HOST": "m"}
    result = mask_env(env)
    keys = [e.key for e in result.entries]
    assert keys == ["Z_KEY", "A_PASSWORD", "M_HOST"]


# ---------------------------------------------------------------------------
# mask_vault
# ---------------------------------------------------------------------------

def test_mask_vault_success(tmp_path):
    vault_file = tmp_path / "secrets.env.age"
    vault_file.write_bytes(b"dummy")
    identity_file = tmp_path / "key.txt"
    identity_file.write_text("AGE-SECRET-KEY-1...")

    plaintext = "DATABASE_PASSWORD=hunter2\nAPP_NAME=myapp\n"
    with patch("envcrypt.env_mask.decrypt", return_value=plaintext):
        result = mask_vault(vault_file, identity_file)

    assert isinstance(result, MaskResult)
    assert result.masked_count == 1
    assert result.as_dict()["APP_NAME"] == "myapp"


def test_mask_vault_decrypt_failure_raises(tmp_path):
    vault_file = tmp_path / "secrets.env.age"
    vault_file.write_bytes(b"dummy")
    identity_file = tmp_path / "key.txt"
    identity_file.write_text("AGE-SECRET-KEY-1...")

    with patch("envcrypt.env_mask.decrypt", side_effect=RuntimeError("bad key")):
        with pytest.raises(MaskError, match="Failed to decrypt vault"):
            mask_vault(vault_file, identity_file)
