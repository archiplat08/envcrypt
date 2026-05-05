"""CLI commands for viewing the envcrypt audit log."""

import click
from pathlib import Path

from envcrypt.audit import read_log


@click.group("audit")
def audit():
    """View and manage the envcrypt audit log."""
    pass


@audit.command("log")
@click.option(
    "--log-file",
    default=".envcrypt_audit.log",
    show_default=True,
    help="Path to the audit log file.",
)
@click.option(
    "--tail",
    "-n",
    default=None,
    type=int,
    help="Show only the last N entries.",
)
@click.option(
    "--action",
    default=None,
    help="Filter entries by action (e.g. encrypt, decrypt).",
)
def log_cmd(log_file: str, tail: int, action: str):
    """Display audit log entries."""
    log_path = Path(log_file)
    entries = read_log(log_path)

    if not entries:
        click.echo("No audit log entries found.")
        return

    if action:
        entries = [e for e in entries if e.get("action") == action]

    if not entries:
        click.echo(f"No entries found for action '{action}'.")
        return

    if tail is not None:
        entries = entries[-tail:]

    for entry in entries:
        actor_part = f" | actor={entry['actor']}" if entry.get("actor") else ""
        file_part = f" | file={entry['file']}" if entry.get("file") else ""
        click.echo(
            f"[{entry['timestamp']}] {entry['action']}{actor_part}{file_part}"
        )


@audit.command("clear")
@click.option(
    "--log-file",
    default=".envcrypt_audit.log",
    show_default=True,
    help="Path to the audit log file.",
)
@click.confirmation_option(prompt="Are you sure you want to clear the audit log?")
def clear_cmd(log_file: str):
    """Clear all audit log entries."""
    log_path = Path(log_file)
    if log_path.exists():
        log_path.unlink()
        click.echo(f"Audit log '{log_file}' cleared.")
    else:
        click.echo("No audit log file found.")
