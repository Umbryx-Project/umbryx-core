"""
Short-lived, single-purpose token for the "link this OIDC identity to my
existing password-based account" confirmation step — deliberately mirrors
core/totp.py's make_mfa_pending_token/decode_mfa_pending_token exactly
(same TTL class, same `type` claim discipline) rather than inventing a
different pattern, per the explicit design constraint from the F1 audit:
a token minted for one stage of auth must carry a `type` that every other
stage's decoder rejects. core/security.py::decode_access_token already
rejects any `type` other than None/"access", so this token is structurally
incapable of being used as a session token — the same property that fixed
F1 for mfa_pending.

Carries the *matched* platform user_id and the OIDC identity to attach —
never trusts the email claim again at confirmation time; the caller must
additionally supply that user's actual password (see
routers/oidc_auth.py::oidc_confirm_link), which is what actually prevents
account takeover via a same/spoofed email at a less-trusted IdP.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

import jwt

from ..config import JWT_ALGO, JWT_SECRET
from ..utils import utcnow

_LINK_TOKEN_TTL_MINUTES = 5


def make_link_pending_token(
    *, matched_user_id: str, provider_id: str, subject: str, email: str
) -> str:
    exp = utcnow() + timedelta(minutes=_LINK_TOKEN_TTL_MINUTES)
    return jwt.encode(
        {
            "type": "oidc_link_pending",
            "matched_user_id": matched_user_id,
            "provider_id": provider_id,
            "subject": subject,
            "email": email,
            "exp": exp,
            "jti": secrets.token_hex(8),
        },
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def decode_link_pending_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "oidc_link_pending":
        return None
    return payload
