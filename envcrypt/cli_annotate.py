"""CLI commands for managing inline key annotations."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_annotate import (
    AnnotateError,
    get_annotation,
    load_annotations,
    remove_annotation,
    set_annotation,
)


@click.group("annotate")
def annotate() -> None:
    """Manage inline annotations for vault keys."""


@annotate.command("set")
@click.argument("vault")
@click.argument("key")
@click.argument("text")
def set_cmd(vault: str, key: str, text: str) -> None:
    """Attach an annotation TEXT to KEY inside VAULT."""
    try:
        updated = set_annotation(Path(vault), key, text)
        click.echo(f"Annotation set for '{key}'. Total annotations: {len(updated)}.")
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@annotate.command("get")
@click.argument("vault")
@click.argument("key")
def get_cmd(vault: str, key: str) -> None:
    """Print the annotation for KEY in VAULT."""
    try:
        text = get_annotation(Path(vault), key)
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    if text is None:
        click.echo(f"No annotation found for '{key}'.")
    else:
        click.echo(text)


@annotate.command("remove")
@click.argument("vault")
@click.argument("key")
def remove_cmd(vault: str, key: str) -> None:
    """Remove the annotation for KEY in VAULT."""
    try:
        remove_annotation(Path(vault), key)
        click.echo(f"Annotation removed for '{key}'.")
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@annotate.command("list")
@click.argument("vault")
def list_cmd(vault: str) -> None:
    """List all annotations stored for VAULT."""
    try:
        annotations = load_annotations(Path(vault))
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    if not annotations:
        click.echo("No annotations found.")
        return
    for key, text in sorted(annotations.items()):
        click.echo(f"{key}: {text}")
