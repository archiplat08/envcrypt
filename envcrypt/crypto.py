"""Core encryption/decryption module using age encryption."""

import subprocess
import tempfile
import os
from pathlib import Path


class AgeEncryptionError(Exception):
    """Raised when encryption or decryption fails."""


def _check_age_installed() -> None:
    """Verify that the age binary is available on PATH."""
    result = subprocess.run(
        ["age", "--version"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AgeEncryptionError(
            "'age' binary not found. Install it from https://github.com/FiloSottile/age"
        )


def encrypt(plaintext: str, recipients: list[str]) -> bytes:
    """
    Encrypt plaintext string for one or more age recipients.

    :param plaintext: The secret content to encrypt.
    :param recipients: List of age public keys or SSH public keys.
    :returns: Encrypted bytes in age binary format.
    :raises AgeEncryptionError: If encryption fails.
    """
    _check_age_installed()
    if not recipients:
        raise AgeEncryptionError("At least one recipient is required.")

    cmd = ["age", "--armor"]
    for recipient in recipients:
        cmd += ["-r", recipient]

    result = subprocess.run(
        cmd,
        input=plaintext,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AgeEncryptionError(f"Encryption failed: {result.stderr.strip()}")

    return result.stdout.encode()


def decrypt(ciphertext: bytes, identity_path: str) -> str:
    """
    Decrypt age-encrypted ciphertext using an identity (private key) file.

    :param ciphertext: The encrypted content as bytes.
    :param identity_path: Path to the age or SSH private key file.
    :returns: Decrypted plaintext string.
    :raises AgeEncryptionError: If decryption fails.
    """
    _check_age_installed()
    identity_path = os.path.expanduser(identity_path)
    if not Path(identity_path).exists():
        raise AgeEncryptionError(f"Identity file not found: {identity_path}")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".age") as tmp:
        tmp.write(ciphertext)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["age", "--decrypt", "-i", identity_path, tmp_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AgeEncryptionError(f"Decryption failed: {result.stderr.strip()}")
        return result.stdout
    finally:
        os.unlink(tmp_path)
