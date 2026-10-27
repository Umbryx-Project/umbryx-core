"""
Encrypted-file-at-rest helper composing core/storage.py's StorageBackend
with core/crypto.py's Fernet encryption.

Nothing else in the codebase combines these: evidence/loot files are
stored as plaintext blobs, and ProjectSecret stores plaintext-shaped
strings, not arbitrary binary files. Raw firewall/router configs often
contain recoverable local-user passwords and SNMP community strings
(security audit precedent), so the raw upload gets the same at-rest
protection as Cred/ProjectSecret values, layered under the existing
StorageBackend rather than duplicating it.
"""

from __future__ import annotations

import io

from .crypto import decrypt_bytes, encrypt_bytes
from .storage import get_storage_backend


async def save_encrypted(project_id: str, filename: str, raw: bytes) -> str:
    backend = get_storage_backend()
    return await backend.save(project_id, filename, io.BytesIO(encrypt_bytes(raw)))


async def load_encrypted(key: str) -> bytes | None:
    backend = get_storage_backend()
    encrypted = await backend.load(key)
    if encrypted is None:
        return None
    return decrypt_bytes(encrypted)
