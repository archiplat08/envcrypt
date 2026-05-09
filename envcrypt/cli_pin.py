"""CLI commands for managing pinned env keys."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_pin import PinError, list_pinned_keys, load_pins, pin_key, unpin_key


@click.group("pin")
def pin() -> None:
    """Pin env keys to fixed values."""


@pin.command("set")
@click.argument("vault")
@click.argument("key")
@click.argument("value")
def set_cmd(vault: str, key: str, value: str) -> None:
    """Pin KEY to VALUE in VAULT."""
    vault_path = Path(vault)
    try:
        pins = pin_key(vault_path, key, value)
        click.echo(f"Pinned {key}={value!r} ({len(pins)} total pins)")
    except PinError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@pin.command("unset")
@click.argument("vault")
@click.argument("key")
def unset_cmd(vault: str, key: str) -> None:
    """Remove pin for KEY in VAULT."""
    vault_path = Path(vault)
    try:
        unpin_key(vault_path, key)
        click.echo(f"Unpinned '{key}'")
    except PinError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@pin.command("list")
@click.argument("vault")
def list_cmd(vault: str) -> None:
    """List all pinned keys in VAULT."""
    vault_path = Path(vault)
    try:
        pins = load_pins(vault_path)
        if not pins:
            click.echo("No pinned keys.")
            return
        for key, value in sorted(pins.items()):
            click.echo(f"{key}={value!r}")
    except PinError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
