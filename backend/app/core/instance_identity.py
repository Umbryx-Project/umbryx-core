"""
Per-instance keypair — the software "electronic key" of the licensing redesign
(docs/modules/LICENSING_REDESIGN.md, Phase 1c).

On first use the instance generates an Ed25519 keypair. The public key is bound
into the license (via the offline C2V→V2C handshake in Phase 2, or the online
check-in in Phase 3); the private key stays local and signs activation requests
and check-ins. This means a copied `.lic` alone won't validate on another box
and can't be re-activated there without the vendor.

Honesty (see the module doc): the private key lives in this instance's own DB,
not a hardware secure element, so a full machine clone carries it — which is why
license binding also uses clone-sensitive hwid params (core/hwid.py). Storing it
in the DB is consistent with the threat model: the key's job is binding and
anti-replay, not secrecy from the box owner.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy.orm import Session

from .. import models

_INSTANCE_PRIVKEY_KEY = "instance_privkey"


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def get_or_create_instance_keypair(db: Session) -> Ed25519PrivateKey:
    """Return this instance's Ed25519 private key, generating and persisting it
    on first call. Idempotent and safe to call from any request."""
    row = db.get(models.GlobalSetting, _INSTANCE_PRIVKEY_KEY)
    if row and (row.value or {}).get("sk"):
        try:
            return Ed25519PrivateKey.from_private_bytes(_b64d(row.value["sk"]))
        except (ValueError, KeyError):
            pass  # corrupt row -> regenerate below
    key = Ed25519PrivateKey.generate()
    sk_b64 = _b64e(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    if row:
        row.value = {"sk": sk_b64}
    else:
        row = models.GlobalSetting(key=_INSTANCE_PRIVKEY_KEY, value={"sk": sk_b64})
        db.add(row)
    db.commit()
    return key


def instance_public_key_b64(db: Session) -> str:
    """The instance's public key (urlsafe-b64, no padding) — bound into the
    license and safe to export in an activation request."""
    key = get_or_create_instance_keypair(db)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return _b64e(pub)


def sign_with_instance_key(db: Session, data: bytes) -> str:
    """Sign bytes with the instance private key; returns urlsafe-b64 signature.
    Used to prove possession of the key in activation requests / online
    check-ins (anti-replay when combined with a server nonce)."""
    return _b64e(get_or_create_instance_keypair(db).sign(data))


def verify_instance_signature(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    """Verify a signature made by an instance key (used by the License Server
    side, and in tests). Never raises — returns False on any problem."""
    try:
        Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64)).verify(
            _b64d(signature_b64), data
        )
        return True
    except (InvalidSignature, ValueError):
        return False
