"""CLI commands for env-sanitize feature."""
from __future__ import annotations

from pathlib import Path
from typing import List

import click

from envcrypt.env_sanitize import SanitizeError, sanitize_vault


@click.group("sanitize")
def sanitize() -> None:
    """Sanitize vault env values."""


@sanitize.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--identity", "-i",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Age identity file for decryption.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(path_type=Path),
    help="Output path (defaults to in-place).",
)
@click.option(
    "--skip", "-s",
    multiple=True,
    metavar="KEY",
    help="Key(s) to skip during sanitization.",
)
def run_cmd(
    vault: Path,
    identity: Path,
    output: Path,
    skip: List[str],
) -> None:
    """Sanitize dangerous characters from vault values."""
    try:
        result = sanitize_vault(
            vault_path=vault,
            identity_path=identity,
            output_path=output,
            skip_keys=list(skip),
        )
    except SanitizeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if result.count() == 0:
        click.echo("No changes needed — vault is already clean.")
    else:
        click.echo(f"Sanitized: {', '.join(result.changed_keys)}")

    click.echo(result.summary())
