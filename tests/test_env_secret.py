"""Tests for envcrypt.env_secret."""
from __future__ import annotations

from pathlib import Path

import pytest

from envcrypt.env_secret import (
    SecretError,
    SecretScanResult,
    _looks_like_secret,
    scan_env,
    scan_env_file,
)


# ---------------------------------------------------------------------------
# _looks_like_secret
# ---------------------------------------------------------------------------

def test_looks_like_secret_hex_token():
    reason = _looks_like_secret("a3f1c9b2e4d7a3f1c9b2e4d7a3f1c9b2")
    assert reason is not None


def test_looks_like_secret_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123"
    reason = _looks_like_secret(jwt)
    assert reason is not None


def test_looks_like_secret_placeholder_ignored():
    assert _looks_like_secret("<your-api-key-here>") is None


def test_looks_like_secret_empty_ignored():
    assert _looks_like_secret("") is None


def test_looks_like_secret_plain_value():
    assert _looks_like_secret("hello") is None


# ---------------------------------------------------------------------------
# scan_env
# ---------------------------------------------------------------------------

def test_scan_env_detects_hex_secret():
    env = {"API_KEY": "a3f1c9b2e4d7a3f1c9b2e4d7a3f1c9b2"}
    result = scan_env(env)
    assert not result.clean
    assert result.findings[0].key == "API_KEY"


def test_scan_env_ignores_non_sensitive_key():
    # Long hex but key name is not sensitive
    env = {"LOG_LEVEL": "a3f1c9b2e4d7a3f1c9b2e4d7a3f1c9b2"}
    result = scan_env(env)
    assert result.clean


def test_scan_env_clean_when_placeholder():
    env = {"SECRET_KEY": "<replace-me>"}
    result = scan_env(env)
    assert result.clean


def test_scan_env_multiple_findings():
    env = {
        "API_KEY": "a3f1c9b2e4d7a3f1c9b2e4d7a3f1c9b2",
        "DB_PASSWORD": "b2e4d7a3f1c9b2e4d7a3f1c9b2e4d7a3",
    }
    result = scan_env(env)
    assert len(result.findings) == 2


def test_scan_result_summary_clean():
    result = SecretScanResult()
    assert "No secrets" in result.summary()


def test_scan_result_summary_with_findings():
    env = {"API_KEY": "a3f1c9b2e4d7a3f1c9b2e4d7a3f1c9b2"}
    result = scan_env(env)
    assert "1 potential" in result.summary()


# ---------------------------------------------------------------------------
# scan_env_file
# ---------------------------------------------------------------------------

def test_scan_env_file_missing_raises(tmp_path):
    with pytest.raises(SecretError):
        scan_env_file(tmp_path / "missing.env")


def test_scan_env_file_detects_secret(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=a3f1c9b2e4d7a3f1c9b2e4d7a3f1c9b2\n")
    result = scan_env_file(env_file)
    assert not result.clean


def test_scan_env_file_clean_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("DEBUG=true\nAPP_NAME=myapp\n")
    result = scan_env_file(env_file)
    assert result.clean
