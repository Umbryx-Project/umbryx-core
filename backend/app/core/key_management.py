"""
Per-project Data Encryption Key (DEK) management.

Hierarchy:
  KEK (Key Encryption Key) = global ENCRYPTION_KEY from .env
    └── DEK (Data Encryption Key) = unique per project, encrypted by KEK
          └── project data (creds, secrets) encrypted by DEK

Security audit (2026-08-29, P1-7): this module's encrypt_for_project/
decrypt_for_project were fully implemented but never called anywhere —
every real write (Cred.secret, ProjectSecret.value_enc) went through
core.crypto.encrypt_str (the global KEK) instead, using the exact same
"__enc__:" sentinel this module also used. That collision made
rotate_project_dek unable to tell which key protected a given value, so it
always failed for any project with real secrets. This module now uses its
own "__pdek__:" sentinel so a ciphertext's prefix alone says which key
protects it.
"""

from cryptography.fernet import Fernet

from .. import models
from .crypto import _get_fernet, decrypt_str
from .utils import ts_now

PDEK_SENTINEL = "__pdek__:"
_SENTINEL = PDEK_SENTINEL  # internal alias, kept short for readability below
_LEGACY_SENTINEL = "__enc__:"  # core.crypto.encrypt_str's sentinel


def is_project_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(_SENTINEL)


def _kek() -> Fernet:
    return _get_fernet()


def generate_dek() -> bytes:
    return Fernet.generate_key()


def encrypt_dek_with_kek(dek: bytes) -> str:
    return _kek().encrypt(dek).decode()


def decrypt_dek_with_kek(dek_enc: str) -> bytes:
    return _kek().decrypt(dek_enc.encode())


def get_or_create_dek(db, project_id: str) -> bytes:
    row = (
        db.query(models.ProjectEncryptionKey)
        .filter(
            models.ProjectEncryptionKey.project_id == project_id,
        )
        .first()
    )
    if row:
        return decrypt_dek_with_kek(row.dek_enc)

    dek = generate_dek()
    dek_enc = encrypt_dek_with_kek(dek)
    row = models.ProjectEncryptionKey(
        project_id=project_id,
        dek_enc=dek_enc,
        created_at=ts_now(),
        version=1,
    )
    db.add(row)
    db.flush()
    return dek


def get_project_fernet(db, project_id: str) -> Fernet:
    dek = get_or_create_dek(db, project_id)
    return Fernet(dek)


def encrypt_for_project(db, project_id: str, plaintext: str) -> str:
    """Encrypt plaintext with this project's DEK, prefixed so it's
    distinguishable from a global-KEK value (see module docstring)."""
    if not plaintext:
        return plaintext
    # Don't double-encrypt — mirrors core.crypto.encrypt_str's guard.
    if plaintext.startswith(_SENTINEL):
        return plaintext
    f = get_project_fernet(db, project_id)
    encrypted = f.encrypt(plaintext.encode()).decode()
    return f"{_SENTINEL}{encrypted}"


def decrypt_for_project(db, project_id: str, value: str) -> str:
    """Decrypt a value written by encrypt_for_project.

    Falls back to the global-KEK decrypt_str() for values still carrying
    the legacy "__enc__:" sentinel — rows the data migration hasn't
    reached yet (or, in a fresh install, values encrypted before this
    project's DEK existed). Once a value is "__pdek__:"-prefixed, a
    decrypt failure propagates (no silent fallback) — same "fail loud"
    principle as core.crypto.decrypt_str (F17): a value that claims to be
    protected by this project's current DEK but can't be decrypted with it
    must not be silently treated as if it were something else.
    """
    if not value:
        return value
    if value.startswith(_SENTINEL):
        f = get_project_fernet(db, project_id)
        return f.decrypt(value[len(_SENTINEL) :].encode()).decode()
    if value.startswith(_LEGACY_SENTINEL):
        return decrypt_str(value)
    return value  # legacy plaintext — return as-is
