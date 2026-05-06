"""CLI commands for linting .env files."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.lint import lint_env_file


@click.group()
def lint() -> None:
    """Lint .env files for common issues."""


@lint.command("check")
@click.argument("env_file", default=".env", type=click.Path(exists=True, path_type=Path))
@click.option("--strict", is_flag=True, default=False, help="Exit non-zero on warnings too.")
def check_cmd(env_file: Path, strict: bool) -> None:
    """Check ENV_FILE for lint issues."""
    result = lint_env_file(env_file)

    if not result.issues:
        click.secho(f"✓ {env_file}: no issues found.", fg="green")
        return

    for issue in result.issues:
        colour = "red" if issue.severity == "error" else "yellow" if issue.severity == "warning" else "blue"
        click.secho(str(issue), fg=colour)

    errors = sum(1 for i in result.issues if i.severity == "error")
    warnings = sum(1 for i in result.issues if i.severity == "warning")
    click.echo(f"\n{errors} error(s), {warnings} warning(s) in {env_file}")

    if result.has_errors or (strict and result.has_warnings):
        raise SystemExit(1)
