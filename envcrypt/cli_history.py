"""CLI commands for vault snapshot history."""
import click
from pathlib import Path

from envcrypt.env_history import (
    HistoryError,
    save_snapshot,
    list_snapshots,
    restore_snapshot,
)


@click.group("history")
def history() -> None:
    """Manage vault snapshot history."""


@history.command("save")
@click.argument("vault", type=click.Path(exists=True, dir_okay=False))
@click.option("--note", default=None, help="Optional note for this snapshot.")
def save_cmd(vault: str, note: str | None) -> None:
    """Save a snapshot of the current vault."""
    try:
        snap = save_snapshot(Path(vault), note=note)
        click.echo(f"Snapshot #{snap.index} saved at {snap.timestamp}")
    except HistoryError as exc:
        raise click.ClickException(str(exc))


@history.command("list")
@click.argument("vault", type=click.Path(dir_okay=False))
def list_cmd(vault: str) -> None:
    """List all snapshots for a vault."""
    snaps = list_snapshots(Path(vault))
    if not snaps:
        click.echo("No snapshots found.")
        return
    for s in snaps:
        note_part = f"  # {s.note}" if s.note else ""
        click.echo(f"[{s.index:>4}] {s.timestamp}{note_part}")


@history.command("restore")
@click.argument("vault", type=click.Path(dir_okay=False))
@click.argument("index", type=int)
def restore_cmd(vault: str, index: int) -> None:
    """Restore the vault to a previous snapshot."""
    try:
        snap = restore_snapshot(Path(vault), index)
        click.echo(f"Restored snapshot #{snap.index} from {snap.timestamp}")
    except HistoryError as exc:
        raise click.ClickException(str(exc))
