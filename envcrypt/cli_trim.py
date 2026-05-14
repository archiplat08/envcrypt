"""CLI commands for the vault trim feature."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_trim import TrimError, trim_vault
from envcrypt.recipients import load_recipients


@click.group()
def trim() -> None:
    """Trim unused keys from a vault using a schema reference."""


@trim.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("schema", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--identity",
    "-i",
    required=True,
    type=click.Path(path_type=Path),
    help="Age identity (private key) file.",
)
@click.option(
    "--recipients-file",
    "-r",
    default=".recipients",
    show_default=True,
    type=click.Path(path_type=Path),
    help="File containing recipient public keys.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(path_type=Path),
    help="Output vault path (defaults to overwriting the source vault).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be removed without modifying the vault.",
)
def run_cmd(
    vault: Path,
    schema: Path,
    identity: Path,
    recipients_file: Path,
    output: Path | None,
    dry_run: bool,
) -> None:
    """Remove keys from VAULT that are absent from SCHEMA."""
    try:
        recipients = load_recipients(recipients_file)
        result = trim_vault(
            vault_path=vault,
            schema_path=schema,
            identity_path=identity,
            recipients=recipients,
            output_path=output,
            dry_run=dry_run,
        )
    except TrimError as exc:
        raise click.ClickException(str(exc)) from exc

    prefix = "[dry-run] " if dry_run else ""
    if result.removed:
        for key in result.removed:
            click.echo(f"{prefix}removed: {key}")
    click.echo(f"{prefix}{result.summary()}")
