"""Tests for envcrypt.template and envcrypt.cli_template."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_template import template
from envcrypt.template import TemplateError, _placeholder_for, generate_template, generate_template_from_vault


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


def test_placeholder_sensitive_key():
    assert _placeholder_for("API_KEY", "abc123") == "<your_api_key>"
    assert _placeholder_for("DB_PASSWORD", "secret") == "<your_db_password>"


def test_placeholder_numeric_value():
    assert _placeholder_for("PORT", "8080") == "0"


def test_placeholder_boolean_value():
    assert _placeholder_for("DEBUG", "true") == "true"
    assert _placeholder_for("ENABLED", "False") == "false"


def test_placeholder_generic_key():
    assert _placeholder_for("APP_NAME", "myapp") == "<app_name>"


# ---------------------------------------------------------------------------
# generate_template
# ---------------------------------------------------------------------------


def test_generate_template_replaces_values():
    env = {"APP_NAME": "myapp", "API_KEY": "supersecret"}
    result = generate_template(env)
    assert "<app_name>" in result
    assert "<your_api_key>" in result
    assert "supersecret" not in result


def test_generate_template_keep_values():
    env = {"APP_NAME": "myapp", "API_KEY": "supersecret"}
    result = generate_template(env, keep_values=True)
    assert "myapp" in result
    assert "supersecret" in result


def test_generate_template_with_header():
    env = {"FOO": "bar"}
    result = generate_template(env, comment_header="Copy this file to .env")
    assert "# Copy this file to .env" in result


# ---------------------------------------------------------------------------
# generate_template_from_vault
# ---------------------------------------------------------------------------


def test_generate_template_from_vault_writes_file(tmp_path):
    vault = tmp_path / ".env.age"
    vault.write_text("encrypted")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1")

    fake_plain = tmp_path / "plain.env"
    fake_plain.write_text("APP_NAME=myapp\nAPI_KEY=secret123\n")

    with patch("envcrypt.template.decrypt_env_file", return_value=fake_plain):
        out = generate_template_from_vault(vault, identity, output_path=tmp_path / ".env.example")

    assert out.exists()
    content = out.read_text()
    assert "APP_NAME" in content
    assert "secret123" not in content


def test_generate_template_from_vault_default_output_name(tmp_path):
    vault = tmp_path / ".env.age"
    vault.write_text("encrypted")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1")

    fake_plain = tmp_path / "plain.env"
    fake_plain.write_text("FOO=bar\n")

    with patch("envcrypt.template.decrypt_env_file", return_value=fake_plain):
        out = generate_template_from_vault(vault, identity)

    assert out.name == ".env.example"


def test_generate_template_from_vault_decrypt_failure_raises(tmp_path):
    vault = tmp_path / ".env.age"
    vault.write_text("encrypted")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1")

    with patch("envcrypt.template.decrypt_env_file", side_effect=RuntimeError("bad key")):
        with pytest.raises(TemplateError, match="Failed to decrypt vault"):
            generate_template_from_vault(vault, identity)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner():
    return CliRunner()


def test_cli_generate_success(runner, tmp_path):
    vault = tmp_path / ".env.age"
    vault.write_text("encrypted")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1")
    output = tmp_path / ".env.example"

    fake_plain = tmp_path / "plain.env"
    fake_plain.write_text("FOO=bar\n")

    with patch("envcrypt.template.decrypt_env_file", return_value=fake_plain):
        result = runner.invoke(
            template,
            ["generate", str(vault), "--identity", str(identity), "--output", str(output)],
        )

    assert result.exit_code == 0
    assert "Template written to" in result.output


def test_cli_generate_failure_shows_error(runner, tmp_path):
    vault = tmp_path / ".env.age"
    vault.write_text("encrypted")
    identity = tmp_path / "key.txt"
    identity.write_text("AGE-SECRET-KEY-1")

    with patch("envcrypt.template.decrypt_env_file", side_effect=RuntimeError("oops")):
        result = runner.invoke(
            template,
            ["generate", str(vault), "--identity", str(identity)],
        )

    assert result.exit_code != 0
    assert "Failed to decrypt vault" in result.output
