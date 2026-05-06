"""Key rotation utilities for re-encrypting vault files with new recipients."""

from pathlib import Path
from typing import Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import parse_dotenv, serialize_dotenv
from envcrypt.recipients import load_recipients
from envcrypt.audit import record


class RotationError(Exception):
    """Raised when key rotation fails."""


def rotate_vault(
    vault_file: str | Path,
    identity_file: str | Path,
    recipients_file: str | Path = ".env.recipients",
    output_file: Optional[str | Path] = None,
    actor: Optional[str] = None,
) -> Path:
    """Re-encrypt a vault file using the current recipients list.

    Decrypts the existing vault with the provided identity, then re-encrypts
    it with all current recipients. Useful after adding or removing a recipient.

    Args:
        vault_file: Path to the encrypted .env.age file.
        identity_file: Path to the age private key used for decryption.
        recipients_file: Path to the recipients file (default: .env.recipients).
        output_file: Destination path. Defaults to overwriting vault_file.
        actor: Optional label recorded in the audit log.

    Returns:
        Path to the (re-)encrypted vault file.

    Raises:
        RotationError: If decryption, parsing, or re-encryption fails.
    """
    vault_path = Path(vault_file)
    output_path = Path(output_file) if output_file else vault_path

    recipients = load_recipients(recipients_file)
    if not recipients:
        raise RotationError(
            f"No recipients found in '{recipients_file}'. "
            "Add at least one recipient before rotating."
        )

    try:
        plaintext = decrypt(str(vault_path), str(identity_file))
    except Exception as exc:
        raise RotationError(f"Failed to decrypt vault for rotation: {exc}") from exc

    try:
        env_vars = parse_dotenv(plaintext)
        canonical = serialize_dotenv(env_vars)
    except Exception as exc:
        raise RotationError(f"Failed to parse decrypted content: {exc}") from exc

    try:
        encrypt(canonical, recipients, str(output_path))
    except Exception as exc:
        raise RotationError(f"Failed to re-encrypt vault: {exc}") from exc

    record(
        "rotate",
        str(output_path),
        actor=actor,
        extra={"recipients_count": len(recipients)},
    )
    return output_path
