"""TOTP helpers for MFA (B8-11)."""

from __future__ import annotations

import secrets
from datetime import timedelta

import jwt
import pyotp

from .config import JWT_ALGO, JWT_SECRET
from .utils import utcnow

_ISSUER = "Umbryx"
_MFA_TOKEN_TTL_MINUTES = 5


def generate_secret() -> str:
    """Return a new base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """Return an otpauth:// URI for QR code generation."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=_ISSUER)


def verify_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code (±1 window tolerance)."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def _consume_timestep(user_id: str, timestep: int) -> bool:
    """AUTH-04 fix: mark a TOTP timestep as used for this user (SET NX).
    Returns False when the timestep was already consumed (replayed code)."""
    if not user_id:
        return True  # flows without a user identity keep plain semantics
    try:
        from .redis_factory import create_redis_sync

        client = create_redis_sync()
        if client is None:
            return True  # Redis unavailable — fail open, codes expire in 30s
        key = f"totp:used:{user_id}:{timestep}"
        return bool(client.set(key, "1", nx=True, ex=120))
    except Exception:
        return True


def verify_code_once(secret: str, code: str, user_id: str = "") -> bool:
    """Verify a 6-digit TOTP code (±1 window) AND consume its timestep so
    the same code cannot be replayed (AUTH-04)."""
    totp = pyotp.TOTP(secret)
    now = int(utcnow().timestamp())
    code = (code or "").strip()
    for drift in (-1, 0, 1):
        ts = now + drift * 30
        if secrets.compare_digest(totp.at(ts), code):
            return _consume_timestep(user_id, int(ts // 30))
    return False


def make_mfa_pending_token(user_id: str) -> str:
    """Return a short-lived JWT that allows only the MFA verify step."""
    exp = utcnow() + timedelta(minutes=_MFA_TOKEN_TTL_MINUTES)
    return jwt.encode(
        {"sub": user_id, "type": "mfa_pending", "exp": exp, "jti": secrets.token_hex(8)},
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def decode_mfa_pending_token(token: str) -> dict | None:
    """Return the payload if the token is a valid mfa_pending token, else None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        if payload.get("type") != "mfa_pending":
            return None
        return payload
    except jwt.PyJWTError:
        return None
