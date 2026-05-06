"""Tests for envcrypt.lint and envcrypt.cli_lint."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from envcrypt.lint import lint_env_file, LintIssue
from envcrypt.cli_lint import lint


@pytest.fixture
def tmp_env(tmp_path: Path):
    def _write(content: str) -> Path:
        p = tmp_path / ".env"
        p.write_text(content)
        return p
    return _write


def test_no_issues_for_clean_file(tmp_env):
    p = tmp_env("DATABASE_URL=postgres://localhost/db\nDEBUG=false\n")
    result = lint_env_file(p)
    assert result.issues == []
    assert not result.has_errors


def test_detects_duplicate_key(tmp_env):
    p = tmp_env("FOO=bar\nFOO=baz\n")
    result = lint_env_file(p)
    dups = [i for i in result.issues if "duplicate" in i.message]
    assert len(dups) == 1
    assert dups[0].severity == "warning"
    assert dups[0].key == "FOO"


def test_detects_placeholder_in_sensitive_key(tmp_env):
    p = tmp_env("API_KEY=changeme\n")
    result = lint_env_file(p)
    errors = [i for i in result.issues if i.severity == "error"]
    assert any("placeholder" in e.message for e in errors)


def test_detects_empty_sensitive_key(tmp_env):
    p = tmp_env('SECRET_TOKEN=""\n')
    result = lint_env_file(p)
    assert result.has_errors


def test_detects_lowercase_key(tmp_env):
    p = tmp_env("my_var=hello\n")
    result = lint_env_file(p)
    warnings = [i for i in result.issues if "uppercase" in i.message]
    assert len(warnings) == 1
    assert warnings[0].severity == "warning"


def test_ignores_comments_and_blanks(tmp_env):
    p = tmp_env("# comment\n\nFOO=bar\n")
    result = lint_env_file(p)
    assert result.issues == []


# --- CLI tests ---


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_check_clean_file(runner, tmp_env):
    p = tmp_env("FOO=bar\n")
    res = runner.invoke(lint, ["check", str(p)])
    assert res.exit_code == 0
    assert "no issues found" in res.output


def test_cli_check_exits_nonzero_on_error(runner, tmp_env):
    p = tmp_env("SECRET=changeme\n")
    res = runner.invoke(lint, ["check", str(p)])
    assert res.exit_code == 1
    assert "ERROR" in res.output


def test_cli_check_strict_exits_nonzero_on_warning(runner, tmp_env):
    p = tmp_env("my_var=hello\n")
    res = runner.invoke(lint, ["check", str(p), "--strict"])
    assert res.exit_code == 1


def test_cli_check_no_strict_exits_zero_on_warning_only(runner, tmp_env):
    p = tmp_env("my_var=hello\n")
    res = runner.invoke(lint, ["check", str(p)])
    assert res.exit_code == 0
