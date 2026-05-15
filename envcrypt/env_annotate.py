"""Inline annotations (comments) for individual env keys stored alongside a vault."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional


class AnnotateError(Exception):
    """Raised when an annotation operation fails."""


def _annotations_path(vault_path: Path) -> Path:
    return vault_path.with_suffix(".annotations.json")


def load_annotations(vault_path: Path) -> Dict[str, str]:
    """Return key -> annotation mapping for *vault_path*.

    Returns an empty dict when no annotation file exists yet.
    """
    path = _annotations_path(vault_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AnnotateError(f"Corrupt annotations file: {exc}") from exc
    if not isinstance(data, dict):
        raise AnnotateError("Annotations file must contain a JSON object.")
    return {str(k): str(v) for k, v in data.items()}


def save_annotations(vault_path: Path, annotations: Dict[str, str]) -> None:
    """Persist *annotations* next to *vault_path*."""
    path = _annotations_path(vault_path)
    path.write_text(json.dumps(annotations, indent=2, sort_keys=True), encoding="utf-8")


def set_annotation(vault_path: Path, key: str, text: str) -> Dict[str, str]:
    """Set the annotation for *key* and return the updated mapping."""
    annotations = load_annotations(vault_path)
    annotations[key] = text
    save_annotations(vault_path, annotations)
    return annotations


def remove_annotation(vault_path: Path, key: str) -> Dict[str, str]:
    """Remove the annotation for *key* (no-op if absent) and return updated mapping."""
    annotations = load_annotations(vault_path)
    annotations.pop(key, None)
    save_annotations(vault_path, annotations)
    return annotations


def get_annotation(vault_path: Path, key: str) -> Optional[str]:
    """Return the annotation text for *key*, or *None* if not set."""
    return load_annotations(vault_path).get(key)
