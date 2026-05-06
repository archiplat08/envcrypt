"""CLI commands for renaming vault keys."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.env_rename import RenameError, rename_key


@click.group()
def rename() -> None:
    """Rename or alias keys inside an encrypted vault."""


@rename.command("key")
@click.argument("old_key")
@click.argument("new_key")
@click.option(
    "--vault",
    default=".env.age",
    show_default=True,
    help="Path to the encrypted vault file.",
)
@click.option(
    "--identity",
    required=True,
    help="Path to the age identity (private key) file.",
)
@click.option(
    "--recipients",
    default=None,
    help="Path to recipients file (defaults to .recipients next to vault).",
)
@click.option(
    "--keep-alias",
    is_flag=True,
    default=False,
    help="Retain the old key as an alias pointing to the same value.",
)
def rename_key_cmd(
    old_key: str,
    new_key: str,
    vault: str,
    identity: str,
    recipients: Optional[str],
    keep_alias: bool,
) -> None:
    """Rename OLD_KEY to NEW_KEY inside the vault."""
    try:
        result = rename_key(
            vault=Path(vault),
            identity=Path(identity),
            old_key=old_key,
            new_key=new_key,
            keep_alias=keep_alias,
            recipients_file=Path(recipients) if recipients else None,
        )
    except RenameError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.aliased:
        click.echo(
            f"Renamed '{result.old_key}' → '{result.new_key}' "
            f"(alias kept) in {result.vault}"
        )
    else:
        click.echo(
            f"Renamed '{result.old_key}' → '{result.new_key}' in {result.vault}"
        )
