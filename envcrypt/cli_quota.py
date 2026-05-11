"""CLI commands for managing vault key quotas."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_quota import QuotaError, load_quota, remove_quota, save_quota


@click.group("quota")
def quota() -> None:
    """Manage key quotas for a vault."""


@quota.command("set")
@click.argument("vault", type=click.Path(dir_okay=False))
@click.argument("limit", type=int)
def set_cmd(vault: str, limit: int) -> None:
    """Set the maximum number of keys allowed in VAULT."""
    try:
        save_quota(Path(vault), limit)
        click.echo(f"Quota set to {limit} key(s) for '{vault}'.")
    except QuotaError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@quota.command("remove")
@click.argument("vault", type=click.Path(dir_okay=False))
def remove_cmd(vault: str) -> None:
    """Remove the quota for VAULT."""
    removed = remove_quota(Path(vault))
    if removed:
        click.echo(f"Quota removed for '{vault}'.")
    else:
        click.echo(f"No quota was set for '{vault}'.")


@quota.command("show")
@click.argument("vault", type=click.Path(dir_okay=False))
def show_cmd(vault: str) -> None:
    """Show the current quota for VAULT."""
    try:
        limit = load_quota(Path(vault))
        if limit is None:
            click.echo(f"No quota configured for '{vault}'.")
        else:
            click.echo(f"Quota for '{vault}': {limit} key(s).")
    except QuotaError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
