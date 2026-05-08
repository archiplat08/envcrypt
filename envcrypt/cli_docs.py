"""CLI commands for managing inline key documentation."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_docs import DocsError, get_doc, load_docs, remove_doc, set_doc


@click.group("docs")
def docs() -> None:
    """Manage inline documentation for vault keys."""


@docs.command("set")
@click.argument("vault")
@click.argument("key")
@click.argument("doc")
def set_cmd(vault: str, key: str, doc: str) -> None:
    """Attach DOC string to KEY in VAULT."""
    try:
        set_doc(Path(vault), key, doc)
        click.echo(f"Documented '{key}'.")
    except DocsError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


@docs.command("get")
@click.argument("vault")
@click.argument("key")
def get_cmd(vault: str, key: str) -> None:
    """Print the documentation for KEY in VAULT."""
    try:
        doc = get_doc(Path(vault), key)
        if doc is None:
            click.echo(f"No documentation found for '{key}'.")
        else:
            click.echo(doc)
    except DocsError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


@docs.command("remove")
@click.argument("vault")
@click.argument("key")
def remove_cmd(vault: str, key: str) -> None:
    """Remove the documentation entry for KEY in VAULT."""
    try:
        removed = remove_doc(Path(vault), key)
        if removed:
            click.echo(f"Removed documentation for '{key}'.")
        else:
            click.echo(f"No documentation entry found for '{key}'.")
    except DocsError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


@docs.command("list")
@click.argument("vault")
def list_cmd(vault: str) -> None:
    """List all documented keys in VAULT."""
    try:
        all_docs = load_docs(Path(vault))
        if not all_docs:
            click.echo("No documentation entries found.")
            return
        for key, doc in sorted(all_docs.items()):
            click.echo(f"{key}: {doc}")
    except DocsError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc
