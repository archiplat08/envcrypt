"""CLI commands for managing secret expiry."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_expire import (
    ExpireError,
    list_expired,
    load_expiry,
    remove_expiry,
    set_expiry,
)


@click.group("expire")
def expire() -> None:
    """Manage expiry dates for vault secrets."""


@expire.command("set")
@click.argument("vault")
@click.argument("key")
@click.argument("expires_at")
@click.option("--note", default="", help="Optional note for this expiry.")
def set_cmd(vault: str, key: str, expires_at: str, note: str) -> None:
    """Set expiry date (ISO-8601) for KEY in VAULT."""
    try:
        info = set_expiry(Path(vault), key, expires_at, note=note)
        click.echo(f"Expiry set: {info.key} expires at {info.expires_at}")
    except ExpireError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@expire.command("remove")
@click.argument("vault")
@click.argument("key")
def remove_cmd(vault: str, key: str) -> None:
    """Remove expiry tracking for KEY in VAULT."""
    try:
        removed = remove_expiry(Path(vault), key)
        if removed:
            click.echo(f"Expiry removed for '{key}'.")
        else:
            click.echo(f"No expiry found for '{key}'.")
    except ExpireError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@expire.command("list")
@click.argument("vault")
@click.option("--expired-only", is_flag=True, help="Show only expired keys.")
def list_cmd(vault: str, expired_only: bool) -> None:
    """List expiry information for VAULT."""
    try:
        if expired_only:
            entries = list_expired(Path(vault))
        else:
            entries = list(load_expiry(Path(vault)).values())
    except ExpireError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if not entries:
        click.echo("No expiry entries found.")
        return

    for info in entries:
        status = "EXPIRED" if info.is_expired() else f"{info.days_remaining():.1f}d remaining"
        note_str = f"  # {info.note}" if info.note else ""
        click.echo(f"  {info.key}: {info.expires_at} [{status}]{note_str}")
