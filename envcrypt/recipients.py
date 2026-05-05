"""Manage recipient public keys for shared secret encryption."""

import json
from pathlib import Path
from typing import List

from envcrypt.crypto import AgeEncryptionError

DEFAULT_RECIPIENTS_FILE = Path(".envcrypt-recipients.json")


def load_recipients(recipients_file: Path = DEFAULT_RECIPIENTS_FILE) -> List[str]:
    """Load recipient public keys from a JSON file.

    Args:
        recipients_file: Path to the recipients JSON file.

    Returns:
        List of age public key strings.

    Raises:
        AgeEncryptionError: If the file is missing or malformed.
    """
    if not recipients_file.exists():
        raise AgeEncryptionError(
            f"Recipients file not found: {recipients_file}. "
            "Run 'envcrypt recipients add <pubkey>' to add recipients."
        )

    try:
        data = json.loads(recipients_file.read_text())
    except json.JSONDecodeError as exc:
        raise AgeEncryptionError(
            f"Failed to parse recipients file: {exc}"
        ) from exc

    recipients = data.get("recipients", [])
    if not isinstance(recipients, list):
        raise AgeEncryptionError("Recipients file must contain a 'recipients' list.")

    return [str(r) for r in recipients if r]


def save_recipients(
    recipients: List[str],
    recipients_file: Path = DEFAULT_RECIPIENTS_FILE,
) -> None:
    """Persist recipient public keys to a JSON file.

    Args:
        recipients: List of age public key strings.
        recipients_file: Path to the recipients JSON file.
    """
    recipients_file.write_text(
        json.dumps({"recipients": recipients}, indent=2) + "\n"
    )


def add_recipient(
    public_key: str,
    recipients_file: Path = DEFAULT_RECIPIENTS_FILE,
) -> List[str]:
    """Add a public key to the recipients file.

    Args:
        public_key: The age public key to add.
        recipients_file: Path to the recipients JSON file.

    Returns:
        Updated list of recipients.

    Raises:
        AgeEncryptionError: If the key is already present.
    """
    if not public_key.startswith("age1"):
        raise AgeEncryptionError(
            f"Invalid age public key (must start with 'age1'): {public_key}"
        )

    existing: List[str] = []
    if recipients_file.exists():
        existing = load_recipients(recipients_file)

    if public_key in existing:
        raise AgeEncryptionError(f"Recipient already exists: {public_key}")

    updated = existing + [public_key]
    save_recipients(updated, recipients_file)
    return updated


def remove_recipient(
    public_key: str,
    recipients_file: Path = DEFAULT_RECIPIENTS_FILE,
) -> List[str]:
    """Remove a public key from the recipients file.

    Args:
        public_key: The age public key to remove.
        recipients_file: Path to the recipients JSON file.

    Returns:
        Updated list of recipients.

    Raises:
        AgeEncryptionError: If the key is not found.
    """
    existing = load_recipients(recipients_file)
    if public_key not in existing:
        raise AgeEncryptionError(f"Recipient not found: {public_key}")

    updated = [k for k in existing if k != public_key]
    save_recipients(updated, recipients_file)
    return updated
