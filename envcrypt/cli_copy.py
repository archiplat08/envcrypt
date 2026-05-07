"""CLI commands for copying keys between vaults."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.env_copy import CopyError, copy_keys


@click.group("copy")
def copy() -> None:
    """Copy keys between encrypted vault files."""


@copy.command("keys")
@click.argument("src", type=click.Path(exists=True, path_type=Path))
@click.argument("dst", type=click.Path(path_type=Path))
@click.option(
    "--identity",
    "-i",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Age identity (private key) file.",
)
@click.option(
    "--key",
    "-k",
    "keys",
    multiple=True,
    help="Key name to copy (repeatable). Copies all keys if omitted.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite existing keys in the destination vault.",
)
@click.option(
    "--recipients",
    "recipients_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Recipients file for the destination vault.",
)
def copy_keys_cmd(
    src: Path,
    dst: Path,
    identity: Path,
    keys: tuple,
    overwrite: bool,
    recipients_file: Optional[Path],
) -> None:
    """Copy keys from SRC vault into DST vault."""
    try:
        result = copy_keys(
            src_vault=src,
            dst_vault=dst,
            identity_file=identity,
            keys=list(keys) if keys else None,
            overwrite=overwrite,
            recipients_file=recipients_file,
        )
    except CopyError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.copied:
        click.echo("Copied keys: " + ", ".join(result.copied))
    if result.skipped:
        click.echo("Skipped (already exist): " + ", ".join(result.skipped))
    click.echo(result.summary)
