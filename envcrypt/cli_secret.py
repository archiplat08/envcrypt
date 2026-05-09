"""CLI commands for secret scanning."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_secret import SecretError, scan_env_file


@click.group("secret")
def secret() -> None:
    """Detect exposed secrets in .env files."""


@secret.command("scan")
@click.argument("env_file", type=click.Path(exists=True, path_type=Path))
@click.option("--strict", is_flag=True, help="Exit non-zero even for warnings.")
def scan_cmd(env_file: Path, strict: bool) -> None:
    """Scan ENV_FILE for values that look like real secrets."""
    try:
        result = scan_env_file(env_file)
    except SecretError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if result.clean:
        click.echo(result.summary())
        return

    click.echo(result.summary())
    for finding in result.findings:
        click.echo(f"  [WARN] {finding}")

    if strict:
        raise SystemExit(1)
