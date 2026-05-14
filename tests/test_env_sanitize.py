"""Tests for envcrypt.env_sanitize."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envcrypt.env_sanitize import (
    SanitizeError,
    SanitizeResult,
    _sanitize_value,
    sanitize_env,
    sanitize_vault,
)


def test_sanitize_value_strips_control_chars():
    assert _sanitize_value("hello\x00world") == "helloworld"


def test_sanitize_value_strips_command_substitution():
    assert _sanitize_value("val$(rm -rf /)") == "valrm -rf /)"


def test_sanitize_value_strips_backtick():
    assert _sanitize_value("`cmd`") == "cmd"


def test_sanitize_value_leaves_clean_value():
    assert _sanitize_value("clean_value123") == "clean_value123"


def test_sanitize_env_detects_changed_keys():
    env = {"KEY": "good", "BAD": "val\x00"}
    result = sanitize_env(env)
    assert "BAD" in result.changed_keys
    assert "KEY" not in result.changed_keys
    assert result.sanitized["BAD"] == "val"
    assert result.sanitized["KEY"] == "good"


def test_sanitize_env_skip_keys_preserved():
    env = {"SKIP_ME": "val\x00", "CLEAN": "ok"}
    result = sanitize_env(env, skip_keys=["SKIP_ME"])
    assert "SKIP_ME" in result.skipped_keys
    assert result.sanitized["SKIP_ME"] == "val\x00"  # unchanged
    assert result.count() == 0


def test_sanitize_result_summary():
    r = SanitizeResult(
        sanitized={},
        changed_keys=["A", "B"],
        skipped_keys=["C"],
    )
    assert "2 key(s) sanitized" in r.summary()
    assert "1 skipped" in r.summary()


def test_sanitize_vault_missing_vault_raises(tmp_path):
    with pytest.raises(SanitizeError, match="Vault not found"):
        sanitize_vault(
            vault_path=tmp_path / "missing.age",
            identity_path=tmp_path / "key.txt",
        )


def test_sanitize_vault_no_recipients_raises(tmp_path):
    vault = tmp_path / "env.age"
    vault.write_bytes(b"data")
    with patch("envcrypt.env_sanitize.load_recipients", return_value=[]):
        with pytest.raises(SanitizeError, match="No recipients"):
            sanitize_vault(vault_path=vault, identity_path=tmp_path / "key.txt")


def test_sanitize_vault_success(tmp_path):
    vault = tmp_path / "env.age"
    vault.write_bytes(b"data")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1...")

    plaintext = "KEY=good\nBAD=val\x00\n"
    recipients = ["age1abc"]

    with patch("envcrypt.env_sanitize.load_recipients", return_value=recipients), \
         patch("envcrypt.env_sanitize.decrypt", return_value=plaintext), \
         patch("envcrypt.env_sanitize.encrypt") as mock_enc:
        result = sanitize_vault(vault_path=vault, identity_path=identity)

    assert "BAD" in result.changed_keys
    assert result.sanitized["BAD"] == "val"
    mock_enc.assert_called_once()
