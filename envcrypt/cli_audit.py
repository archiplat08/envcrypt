import click
import json
from envcrypt.audit import read_log, record
from pathlib import Path

DEFAULT_LOG = ".envcrypt_audit.log"


@click.group()
def audit():
    """Manage the envcrypt audit log."""
    pass


@audit.command("log")
@click.option("--log-file", default=DEFAULT_LOG, show_default=True, help="Path to audit log file.")
@click.option("--action", default=None, help="Filter entries by action.")
@click.option("--actor", default=None, help="Filter entries by actor.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def log_cmd(log_file, action, actor, as_json):
    """Display the audit log."""
    entries = read_log(log_file)

    if action:
        entries = [e for e in entries if e.get("action") == action]
    if actor:
        entries = [e for e in entries if e.get("actor") == actor]

    if not entries:
        click.echo("No audit log entries found.")
        return

    if as_json:
        click.echo(json.dumps(entries, indent=2))
    else:
        for entry in entries:
            ts = entry.get("timestamp", "?")
            act = entry.get("action", "?")
            detail = entry.get("detail", "")
            actor_str = f" [{entry['actor']}]" if entry.get("actor") else ""
            click.echo(f"{ts}{actor_str}  {act}  {detail}")


@audit.command("clear")
@click.option("--log-file", default=DEFAULT_LOG, show_default=True, help="Path to audit log file.")
@click.confirmation_option(prompt="Are you sure you want to clear the audit log?")
def clear_cmd(log_file):
    """Clear the audit log."""
    path = Path(log_file)
    if path.exists():
        path.unlink()
        click.echo(f"Audit log '{log_file}' cleared.")
    else:
        click.echo("No audit log file found.")
