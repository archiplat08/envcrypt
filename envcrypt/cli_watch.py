"""CLI commands for the vault-watch feature."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_watch import WatchError, WatchEvent, watch_vault


@click.group()
def watch() -> None:
    """Watch a vault file for changes."""


@watch.command("start")
@click.argument("vault", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--interval",
    default=2.0,
    show_default=True,
    help="Polling interval in seconds.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress the initial 'watching' message.",
)
def start_cmd(vault: str, interval: float, quiet: bool) -> None:
    """Watch VAULT and print a notification whenever it changes."""
    vault_path = Path(vault)

    if not quiet:
        click.echo(f"Watching {vault_path} (interval={interval}s) — Ctrl-C to stop.")

    def _on_change(event: WatchEvent) -> None:
        if event.is_first_seen:
            click.echo(f"[watch] Initial snapshot recorded for {event.vault.name}.")
        else:
            click.echo(
                f"[watch] Change detected in {event.vault.name} "
                f"(hash: {event.new_hash[:12]}…)"
            )

    try:
        watch_vault(vault_path, _on_change, interval=interval)
    except WatchError as exc:
        raise click.ClickException(str(exc)) from exc
    except KeyboardInterrupt:
        click.echo("\n[watch] Stopped.")
