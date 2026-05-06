"""Tests for envcrypt.validate and envcrypt.cli_validate."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from envcrypt.validate import (
    ValidationResult,
    load_schema,
    validate_env,
    validate_env_file,
)
from envcrypt.cli_validate import validate


# ---------------------------------------------------------------------------
# validate_env unit tests
# ---------------------------------------------------------------------------

def test_validate_env_all_present():
    env = {"DB_URL": "postgres://localhost", "SECRET": "abc"}
    result = validate_env(env, ["DB_URL", "SECRET"])
    assert result.ok


def test_validate_env_missing_key():
    env = {"DB_URL": "postgres://localhost"}
    result = validate_env(env, ["DB_URL", "SECRET"])
    assert not result.ok
    assert any(i.key == "SECRET" and "missing" in i.message for i in result.issues)


def test_validate_env_empty_value_flagged():
    env = {"DB_URL": "", "SECRET": "abc"}
    result = validate_env(env, ["DB_URL", "SECRET"])
    assert not result.ok
    assert any(i.key == "DB_URL" and "empty" in i.message for i in result.issues)


def test_validate_env_empty_allowed():
    env = {"DB_URL": "", "SECRET": "abc"}
    result = validate_env(env, ["DB_URL", "SECRET"], allow_empty=True)
    assert result.ok


def test_validation_result_str_ok():
    result = ValidationResult()
    assert "All required" in str(result)


def test_validation_result_str_errors():
    result = ValidationResult()
    from envcrypt.validate import ValidationIssue
    result.issues.append(ValidationIssue("FOO", "missing"))
    text = str(result)
    assert "FOO" in text and "missing" in text


# ---------------------------------------------------------------------------
# load_schema
# ---------------------------------------------------------------------------

def test_load_schema_parses_keys(tmp_path: Path):
    schema = tmp_path / "schema.txt"
    schema.write_text("# comment\nDB_URL\nSECRET\n\nAPI_KEY\n")
    keys = load_schema(schema)
    assert keys == ["DB_URL", "SECRET", "API_KEY"]


# ---------------------------------------------------------------------------
# validate_env_file
# ---------------------------------------------------------------------------

def test_validate_env_file_success(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text('DB_URL="postgres://localhost"\nSECRET="abc"\n')
    schema = tmp_path / "schema.txt"
    schema.write_text("DB_URL\nSECRET\n")
    result = validate_env_file(env_file, schema)
    assert result.ok


def test_validate_env_file_failure(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text('DB_URL="postgres://localhost"\n')
    schema = tmp_path / "schema.txt"
    schema.write_text("DB_URL\nSECRET\n")
    result = validate_env_file(env_file, schema)
    assert not result.ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner():
    return CliRunner()


def test_cli_check_passes(tmp_path: Path, runner: CliRunner):
    env_file = tmp_path / ".env"
    env_file.write_text('KEY="value"\n')
    schema = tmp_path / "schema.txt"
    schema.write_text("KEY\n")
    result = runner.invoke(validate, ["check", str(env_file), str(schema)])
    assert result.exit_code == 0
    assert "All required" in result.output


def test_cli_check_fails(tmp_path: Path, runner: CliRunner):
    env_file = tmp_path / ".env"
    env_file.write_text('KEY="value"\n')
    schema = tmp_path / "schema.txt"
    schema.write_text("KEY\nMISSING\n")
    result = runner.invoke(validate, ["check", str(env_file), str(schema)])
    assert result.exit_code == 1
