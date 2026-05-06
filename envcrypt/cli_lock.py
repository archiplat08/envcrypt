"""CLI commands for vault locking."""
from __future__ import annotations

import sys
from pathlib import Path

import click

from envcrypt.env_lock import LockError, is_locked, lock_vault, read_lock_info, unlock_vault


@click.group()
def lock() -> None:
    """Lock and unlock vault files to prevent accidental modifications."""


@lock.command("lock")
@click.argument("vault", default=".env.age")
@click.option("--actor", default=None, help="Name or email of the person locking the vault.")
def lock_cmd(vault: str, actor: str | None) -> None:
    """Lock VAULT to prevent modifications."""
    vault_path = Path(vault)
    try:
        info = lock_vault(vault_path, actor=actor)
    except LockError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    who = f" by {info.locked_by}" if info.locked_by else ""
    click.echo(f"Locked {vault}{who} at {info.locked_at}")


@lock.command("unlock")
@click.argument("vault", default=".env.age")
def unlock_cmd(vault: str) -> None:
    """Unlock VAULT."""
    vault_path = Path(vault)
    try:
        unlock_vault(vault_path)
    except LockError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Unlocked {vault}")


@lock.command("status")
@click.argument("vault", default=".env.age")
def status_cmd(vault: str) -> None:
    """Show lock status of VAULT."""
    vault_path = Path(vault)
    if not is_locked(vault_path):
        click.echo(f"{vault}: unlocked")
        return
    try:
        info = read_lock_info(vault_path)
    except LockError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    who = f" (locked by {info.locked_by})" if info.locked_by else ""
    click.echo(f"{vault}: locked at {info.locked_at}{who}")
