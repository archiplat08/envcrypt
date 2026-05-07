"""Tests for envcrypt.env_redact."""
import pytest

from envcrypt.env_redact import (
    RedactResult,
    _is_sensitive,
    redact_env,
)


# ---------------------------------------------------------------------------
# _is_sensitive
# ---------------------------------------------------------------------------

def test_is_sensitive_password_key():
    assert _is_sensitive("DB_PASSWORD") is True


def test_is_sensitive_token_key():
    assert _is_sensitive("GITHUB_TOKEN") is True


def test_is_sensitive_api_key():
    assert _is_sensitive("STRIPE_API_KEY") is True


def test_is_sensitive_non_sensitive_key():
    assert _is_sensitive("APP_ENV") is False


def test_is_sensitive_extra_pattern():
    assert _is_sensitive("MY_CUSTOM_CRED", extra_patterns=["*CRED*"]) is True


def test_is_sensitive_case_insensitive():
    assert _is_sensitive("db_secret") is True


# ---------------------------------------------------------------------------
# redact_env
# ---------------------------------------------------------------------------

def test_redact_env_replaces_sensitive_values():
    env = {"DB_PASSWORD": "supersecret", "APP_ENV": "production"}
    result = redact_env(env)
    assert result.redacted["DB_PASSWORD"] == "***"
    assert result.redacted["APP_ENV"] == "production"


def test_redact_env_tracks_redacted_keys():
    env = {"API_KEY": "abc123", "HOST": "localhost"}
    result = redact_env(env)
    assert "API_KEY" in result.redacted_keys
    assert "HOST" not in result.redacted_keys


def test_redact_env_count():
    env = {"SECRET_KEY": "x", "AUTH_TOKEN": "y", "PORT": "8080"}
    result = redact_env(env)
    assert result.count == 2


def test_redact_env_no_sensitive_keys():
    env = {"APP_ENV": "dev", "PORT": "3000"}
    result = redact_env(env)
    assert result.count == 0
    assert result.redacted == env


def test_redact_env_partial_shows_first_last():
    env = {"DB_PASSWORD": "mysecret"}
    result = redact_env(env, partial=True)
    assert result.redacted["DB_PASSWORD"] == "m***t"


def test_redact_env_partial_short_value_fully_redacted():
    env = {"DB_PASSWORD": "x"}
    result = redact_env(env, partial=True)
    assert result.redacted["DB_PASSWORD"] == "***"


def test_redact_env_extra_patterns():
    env = {"MY_WEBHOOK_URL": "https://hooks.example.com", "NAME": "alice"}
    result = redact_env(env, extra_patterns=["*WEBHOOK*"])
    assert result.redacted["MY_WEBHOOK_URL"] == "***"
    assert result.redacted["NAME"] == "alice"


def test_redact_result_summary_with_redacted_keys():
    result = RedactResult(
        redacted={"DB_PASSWORD": "***"},
        redacted_keys=["DB_PASSWORD"],
    )
    assert "1 key(s) redacted" in result.summary()
    assert "DB_PASSWORD" in result.summary()


def test_redact_result_summary_no_redacted_keys():
    result = RedactResult(redacted={"PORT": "8080"}, redacted_keys=[])
    assert result.summary() == "No keys redacted."


def test_redact_env_does_not_mutate_original():
    env = {"DB_PASSWORD": "secret", "APP": "myapp"}
    original = dict(env)
    redact_env(env)
    assert env == original
