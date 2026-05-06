"""CLI commands for sharing encrypted vaults."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.share import ShareError, share_subset, share_vault


@click.group()
def share() -> None:
    """Share encrypted vaults with specific recipients."""


@share.command("vault")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("identity", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-r",
    "--recipient",
    "recipients",
    multiple=True,
    help="Recipient public key (age1…). May be repeated.",
)
@click.option(
    "-k",
    "--keys-file",
    type=click.Path(path_type=Path),
    default=None,
    help="Load recipients from a keys file instead of --recipient flags.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output path for the shared vault.",
)
def share_vault_cmd(
    vault: Path,
    identity: Path,
    recipients: tuple,
    keys_file: Optional[Path],
    output: Optional[Path],
) -> None:
    """Re-encrypt VAULT for a set of recipients."""
    try:
        out = share_vault(
            vault_path=vault,
            identity_file=identity,
            recipients=list(recipients),
            output_path=output,
            keys_file=keys_file,
        )
        click.echo(f"Shared vault written to: {out}")
    except ShareError as exc:
        raise click.ClickException(str(exc)) from exc


@share.command("subset")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("identity", type=click.Path(exists=True, path_type=Path))
@click.option("-k", "--key", "keys", multiple=True, required=True, help="Env key to include.")
@click.option(
    "-r",
    "--recipient",
    "recipients",
    multiple=True,
    required=True,
    help="Recipient public key.",
)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
def share_subset_cmd(
    vault: Path,
    identity: Path,
    keys: tuple,
    recipients: tuple,
    output: Optional[Path],
) -> None:
    """Share only selected env KEYS from VAULT with recipients."""
    try:
        out = share_subset(
            vault_path=vault,
            identity_file=identity,
            keys=list(keys),
            recipients=list(recipients),
            output_path=output,
        )
        click.echo(f"Subset vault written to: {out}")
    except ShareError as exc:
        raise click.ClickException(str(exc)) from exc
