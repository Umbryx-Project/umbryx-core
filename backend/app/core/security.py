import re
import secrets
import string
from datetime import timedelta

import jwt
from passlib.context import CryptContext

from .. import models
from ..core.utils import utcnow
from .config import JWT_ALGO, JWT_EXPIRE_HOURS, JWT_REFRESH_EXPIRE_HOURS, JWT_SECRET

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

_ALPHABET = string.ascii_letters + string.digits

_PASSWORD_MIN_LEN = 12


def validate_password_strength(password: str) -> None:
    if len(password) < _PASSWORD_MIN_LEN:
        raise ValueError(f"Password must be at least {_PASSWORD_MIN_LEN} characters")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")


def gen_password(length: int = 12) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


# Fixed bcrypt hash used only as filler when there's no real password_hash
# to check against (missing user, or an OIDC-only account with
# password_hash=""). Verifying against it still pays bcrypt's ~200ms cost,
# so a login for a nonexistent username takes the same time as a wrong
# password against a real one — a None short-circuit that skipped the
# bcrypt call entirely made the two cases distinguishable by response
# timing alone (user-enumeration side channel, security retest, 2026-09-03).
_DUMMY_HASH = pwd_ctx.hash("umbryx-timing-parity-filler-value")


def verify_password(plain: str, hashed: str | None) -> bool:
    """False (never an exception) for a blank/unparseable/missing hash —
    OIDC-only accounts (routers/oidc_auth.py JIT provisioning) are created
    with password_hash="" since they have no platform password at all, and
    a guessed username against one of those (or a username that doesn't
    exist at all) must fail cleanly with a normal 401, not a 500 from
    passlib rejecting the hash format.

    Always runs a real bcrypt verify (against `_DUMMY_HASH` when `hashed`
    is falsy) rather than short-circuiting, so callers can pass this a
    `None` hash for a not-found user and still get constant-time-ish
    behaviour relative to a real wrong-password check."""
    try:
        ok = pwd_ctx.verify(plain, hashed or _DUMMY_HASH)
    except (ValueError, TypeError):
        return False
    return ok and bool(hashed)


def make_token(user: models.User) -> str:
    exp = utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode(
        {
            "sub": user.id,
            "username": user.username,
            "role": user.role,
            "exp": exp,
            "jti": secrets.token_hex(16),
        },
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def make_refresh_token(user: models.User) -> str:
    exp = utcnow() + timedelta(hours=JWT_REFRESH_EXPIRE_HOURS)
    return jwt.encode(
        {
            "sub": user.id,
            "username": user.username,
            "role": user.role,
            "type": "refresh",
            "exp": exp,
            "jti": secrets.token_hex(16),
        },
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def make_stream_token(user: models.User, expires_minutes: int = 2) -> str:
    """Short-lived token for SSE/EventSource connections, which can't set
    an Authorization header — passed as `?token=` instead (see
    auth_middleware in main.py, which requires `type == "stream"` and its
    own 120s `iat`-based expiry check on top of `exp`)."""
    now = utcnow()
    return jwt.encode(
        {
            "sub": user.id,
            "username": user.username,
            "role": user.role,
            "type": "stream",
            "iat": int(now.timestamp()),
            "exp": now + timedelta(minutes=expires_minutes),
            "jti": secrets.token_hex(16),
        },
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None


def decode_access_token(token: str) -> dict | None:
    """Like decode_token, but rejects any special-purpose token (mfa_pending,
    refresh, stream, ...). Only a full access token (no `type` claim, or
    `type == "access"`) authenticates a normal API request."""
    payload = decode_token(token)
    if payload is None:
        return None
    if payload.get("type") not in (None, "access"):
        return None
    return payload


def token_response(user: models.User) -> dict:
    from .. import schemas

    return {
        "access_token": make_token(user),
        "refresh_token": make_refresh_token(user),
        "token_type": "bearer",
        "user": schemas.UserOut.model_validate(user).model_dump(),
    }
