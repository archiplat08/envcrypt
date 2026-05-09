"""CLI commands for env key group management."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from envcrypt.env_group import (
    GroupError,
    add_key_to_group,
    delete_group,
    groups_for_key,
    keys_in_group,
    load_groups,
    remove_key_from_group,
)


@click.group("group")
def group() -> None:
    """Manage named groups of env keys."""


@group.command("add")
@click.argument("vault")
@click.argument("group_name")
@click.argument("key")
def add_cmd(vault: str, group_name: str, key: str) -> None:
    """Add KEY to GROUP_NAME in VAULT."""
    try:
        add_key_to_group(Path(vault), group_name, key)
        click.echo(f"Added '{key}' to group '{group_name}'.")
    except GroupError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@group.command("remove")
@click.argument("vault")
@click.argument("group_name")
@click.argument("key")
def remove_cmd(vault: str, group_name: str, key: str) -> None:
    """Remove KEY from GROUP_NAME in VAULT."""
    try:
        remove_key_from_group(Path(vault), group_name, key)
        click.echo(f"Removed '{key}' from group '{group_name}'.")
    except GroupError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@group.command("delete")
@click.argument("vault")
@click.argument("group_name")
def delete_cmd(vault: str, group_name: str) -> None:
    """Delete GROUP_NAME entirely from VAULT."""
    try:
        delete_group(Path(vault), group_name)
        click.echo(f"Deleted group '{group_name}'.")
    except GroupError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@group.command("list")
@click.argument("vault")
@click.option("--group", "group_name", default=None, help="Filter to a specific group.")
def list_cmd(vault: str, group_name: str | None) -> None:
    """List groups (and their keys) in VAULT."""
    try:
        if group_name:
            members = keys_in_group(Path(vault), group_name)
            for k in members:
                click.echo(f"  {k}")
        else:
            groups = load_groups(Path(vault))
            if not groups:
                click.echo("No groups defined.")
                return
            for g, members in groups.items():
                click.echo(f"{g}: {', '.join(members)}")
    except GroupError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@group.command("which")
@click.argument("vault")
@click.argument("key")
def which_cmd(vault: str, key: str) -> None:
    """Show which groups KEY belongs to in VAULT."""
    gs = groups_for_key(Path(vault), key)
    if not gs:
        click.echo(f"'{key}' is not in any group.")
    else:
        click.echo(", ".join(gs))
