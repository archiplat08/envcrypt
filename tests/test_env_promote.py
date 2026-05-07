"""Tests for envcrypt.env_promote."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from envcrypt.env_promote import promote_vault, PromoteError, PromoteResult


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    return tmp_path / "staging.env.age"


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(decrypt_return: str, monkeypatch):
    monkeypatch.setattr("envcrypt.env_promote.decrypt", lambda *a, **kw: decrypt_return)
    monkeypatch.setattr("envcrypt.env_promote.encrypt", lambda *a, **kw: None)
    monkeypatch.setattr(
        "envcrypt.env_promote.load_recipients",
        lambda *a, **kw: ["age1abc"],
    )


def test_promote_vault_success(tmp_path, vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"encrypted")
    dest = tmp_path / "prod.env.age"
    _patch_crypto("KEY1=val1\nKEY2=val2\n", monkeypatch)

    result = promote_vault(vault_file, dest, identity_file)

    assert isinstance(result, PromoteResult)
    assert set(result.promoted_keys) == {"KEY1", "KEY2"}
    assert result.skipped_keys == []
    assert result.destination == dest


def test_promote_vault_include_filter(tmp_path, vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"encrypted")
    dest = tmp_path / "prod.env.age"
    _patch_crypto("KEY1=val1\nKEY2=val2\nKEY3=val3\n", monkeypatch)

    result = promote_vault(vault_file, dest, identity_file, include_keys=["KEY1", "KEY3"])

    assert result.promoted_keys == ["KEY1", "KEY3"]
    assert "KEY2" in result.skipped_keys


def test_promote_vault_exclude_filter(tmp_path, vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"encrypted")
    dest = tmp_path / "prod.env.age"
    _patch_crypto("KEY1=val1\nSECRET=topsecret\n", monkeypatch)

    result = promote_vault(vault_file, dest, identity_file, exclude_keys=["SECRET"])

    assert result.promoted_keys == ["KEY1"]
    assert "SECRET" in result.skipped_keys


def test_promote_vault_no_overwrite_keeps_dest_value(
    tmp_path, vault_file, identity_file, monkeypatch
):
    vault_file.write_bytes(b"encrypted")
    dest = tmp_path / "prod.env.age"
    dest.write_bytes(b"encrypted_dest")

    call_count = 0

    def _fake_decrypt(path, ident):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return "KEY1=new_value\n"
        return "KEY1=old_value\n"

    monkeypatch.setattr("envcrypt.env_promote.decrypt", _fake_decrypt)
    monkeypatch.setattr("envcrypt.env_promote.encrypt", lambda *a, **kw: None)
    monkeypatch.setattr("envcrypt.env_promote.load_recipients", lambda *a, **kw: ["age1abc"])

    result = promote_vault(vault_file, dest, identity_file, overwrite=False)

    assert "KEY1" in result.skipped_keys


def test_promote_vault_missing_source_raises(tmp_path, identity_file):
    with pytest.raises(PromoteError, match="Source vault not found"):
        promote_vault(tmp_path / "ghost.age", tmp_path / "dest.age", identity_file)


def test_promote_vault_no_recipients_raises(tmp_path, vault_file, identity_file, monkeypatch):
    vault_file.write_bytes(b"encrypted")
    monkeypatch.setattr("envcrypt.env_promote.load_recipients", lambda *a, **kw: [])

    with pytest.raises(PromoteError, match="No recipients"):
        promote_vault(vault_file, tmp_path / "dest.age", identity_file)


def test_promote_result_summary(tmp_path):
    r = PromoteResult(
        source=Path("src.age"),
        destination=Path("dst.age"),
        promoted_keys=["A", "B"],
        skipped_keys=["C"],
    )
    assert "2 key(s)" in r.summary
    assert "1 skipped" in r.summary
