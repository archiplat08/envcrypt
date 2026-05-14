"""CLI commands for managing vault notification hooks."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_notify import NotifyError, add_hook, fire_hooks, load_hooks, remove_hook


@click.group("notify")
def notify() -> None:
    """Manage notification hooks for vault events."""


@notify.command("add")
@click.argument("vault")
@click.option("--event", required=True, help="Event name (e.g. encrypt, rotate, share).")
@click.option("--command", required=True, help="Shell command to run. Use {vault} and {event} as placeholders.")
def add_cmd(vault: str, event: str, command: str) -> None:
    """Add a hook for an event."""
    try:
        hooks = add_hook(Path(vault), event, command)
        click.echo(f"Hook added. Total hooks for '{event}': {sum(1 for h in hooks if h.event == event)}")
    except NotifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@notify.command("remove")
@click.argument("vault")
@click.option("--event", required=True, help="Event name whose hooks should be removed.")
def remove_cmd(vault: str, event: str) -> None:
    """Remove all hooks for an event."""
    try:
        remove_hook(Path(vault), event)
        click.echo(f"All hooks for event '{event}' removed.")
    except NotifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@notify.command("list")
@click.argument("vault")
def list_cmd(vault: str) -> None:
    """List all hooks configured for a vault."""
    try:
        hooks = load_hooks(Path(vault))
    except NotifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if not hooks:
        click.echo("No hooks configured.")
        return

    for h in hooks:
        status = "enabled" if h.enabled else "disabled"
        click.echo(f"[{h.event}] ({status}) {h.command}")


@notify.command("fire")
@click.argument("vault")
@click.option("--event", required=True, help="Event name to fire.")
@click.option("--actor", default=None, help="Optional actor name substituted as {actor}.")
def fire_cmd(vault: str, event: str, actor: str | None) -> None:
    """Manually fire all hooks for an event."""
    try:
        count = fire_hooks(Path(vault), event, actor=actor)
        click.echo(f"Fired {count} hook(s) for event '{event}'.")
    except NotifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
