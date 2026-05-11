"""CLI commands for vault access log management."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.env_access import (
    AccessError,
    filter_access_log,
    clear_access_log,
)


@click.group("access")
def access() -> None:
    """Manage the vault access log."""


@access.command("log")
@click.argument("vault", type=click.Path(exists=True))
@click.option("--action", default=None, help="Filter by action (read/write/delete).")
@click.option("--key", default=None, help="Filter by key name.")
@click.option("--actor", default=None, help="Filter by actor.")
def log_cmd(
    vault: str,
    action: Optional[str],
    key: Optional[str],
    actor: Optional[str],
) -> None:
    """Show the access log for a vault."""
    try:
        entries = filter_access_log(Path(vault), action=action, key=key, actor=actor)
    except AccessError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if not entries:
        click.echo("No access log entries found.")
        return

    for entry in entries:
        click.echo(str(entry))


@access.command("clear")
@click.argument("vault", type=click.Path(exists=True))
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def clear_cmd(vault: str, yes: bool) -> None:
    """Clear the access log for a vault."""
    if not yes:
        click.confirm("Clear the access log? This cannot be undone.", abort=True)
    try:
        count = clear_access_log(Path(vault))
    except AccessError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    click.echo(f"Cleared {count} access log entries.")
