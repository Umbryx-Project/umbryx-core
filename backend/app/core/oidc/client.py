"""
Minimal, dependency-light OIDC relying-party client: discovery, PKCE,
authorization-code exchange, and full id_token validation (signature via
JWKS, iss/aud/exp/nonce). Hand-rolled with httpx + PyJWT rather than a
third-party OIDC library so every outbound call can be routed through the
platform's own ssrf_guard and JWKS caching stays under our control (a
library's built-in JWKS client typically fetches directly with urllib,
bypassing both).

No network call in this module skips core.ssrf_guard.validate_outbound_url —
issuer/token/JWKS URLs are all admin-supplied (org OIDC provider config),
which makes them exactly the class of user-controlled outbound target the
guard exists for.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

from ..ssrf_guard import validate_outbound_url

_HTTP_TIMEOUT = 10.0
_JWKS_CACHE_TTL_SECONDS = 600
_SUPPORTED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")


class OIDCError(Exception):
    """Any failure in the OIDC flow — discovery, exchange, or token
    validation. Deliberately one exception type: callers must always fail
    closed (reject the login) rather than pattern-match on subtypes and
    risk treating some failure as non-fatal."""


def _check_ssrf(url: str, allow_private: bool = False) -> None:
    # validate_outbound_url raises fastapi.HTTPException — translated to
    # OIDCError here so every caller of this module only ever needs to
    # catch one exception type (see OIDCError's docstring). allow_private
    # is per-provider (OIDCProvider.allow_private_issuer, settable only by
    # a platform_admin — see routers/oidc_admin.py), never a blanket
    # module-level default.
    try:
        validate_outbound_url(url, allow_private=allow_private)
    except Exception as exc:  # fastapi.HTTPException, deliberately caught broadly
        raise OIDCError(f"Blocked outbound request to {url}: {exc}") from exc


def _get(url: str, allow_private: bool = False, **kwargs) -> httpx.Response:
    _check_ssrf(url, allow_private)
    try:
        resp = httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=False, **kwargs)
    except httpx.HTTPError as exc:
        raise OIDCError(f"Request to {url} failed: {exc}") from exc
    if resp.status_code >= 400:
        raise OIDCError(f"Request to {url} returned HTTP {resp.status_code}")
    return resp


def _post(url: str, allow_private: bool = False, **kwargs) -> httpx.Response:
    _check_ssrf(url, allow_private)
    try:
        resp = httpx.post(url, timeout=_HTTP_TIMEOUT, follow_redirects=False, **kwargs)
    except httpx.HTTPError as exc:
        raise OIDCError(f"Request to {url} failed: {exc}") from exc
    if resp.status_code >= 400:
        raise OIDCError(f"Request to {url} returned HTTP {resp.status_code}: {resp.text[:300]}")
    return resp


@dataclass
class DiscoveryResult:
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str


def discover(issuer_url: str, allow_private: bool = False) -> DiscoveryResult:
    """GET {issuer}/.well-known/openid-configuration. Never accepts
    hand-entered endpoint URLs per spec — this is the only path that
    populates them."""
    issuer_url = issuer_url.rstrip("/")
    doc = _get(f"{issuer_url}/.well-known/openid-configuration", allow_private).json()
    missing = [
        k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not doc.get(k)
    ]
    if missing:
        raise OIDCError(f"Discovery document missing required field(s): {', '.join(missing)}")
    # Every endpoint the discovery doc hands back is itself outbound-called
    # later (token exchange, JWKS fetch) — validate here too so a
    # malicious/compromised issuer can't discovery its way to an internal
    # target even though the issuer_url itself passed the guard.
    for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
        if doc.get(key):
            _check_ssrf(doc[key], allow_private)
    return DiscoveryResult(
        authorization_endpoint=doc["authorization_endpoint"],
        token_endpoint=doc["token_endpoint"],
        userinfo_endpoint=doc.get("userinfo_endpoint", ""),
        jwks_uri=doc["jwks_uri"],
    )


def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256 — required,
    not optional, for every authorization-code request this client makes."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def build_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    nonce: str,
    code_challenge: str,
    allow_private: bool = False,
) -> str:
    _check_ssrf(authorization_endpoint, allow_private)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes or ["openid", "email", "profile"]),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


def exchange_code(
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    allow_private: bool = False,
) -> dict:
    """Authorization-code + PKCE token exchange. Sending client_secret
    alongside code_verifier is intentional — PKCE defends the public/
    front-channel leg (a stolen `code`), it doesn't replace confidential-
    client authentication where the IdP issued a secret."""
    resp = _post(
        token_endpoint,
        allow_private,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
        },
        headers={"Accept": "application/json"},
    )
    data = resp.json()
    if "id_token" not in data:
        raise OIDCError("Token response did not include id_token")
    return data


# jwks_uri -> (PyJWKClient, cached_at). PyJWKClient does its own internal
# per-kid caching (lifespan=default) but we still bound how long a given
# client instance (and thus its key cache) lives, so a rotated/revoked key
# is never trusted indefinitely — and a lookup for an unknown kid forces
# PyJWKClient to hit the JWKS endpoint again rather than trusting a stale
# local set forever.
_jwks_client_cache: dict[str, tuple[PyJWKClient, float]] = {}


def _get_jwks_client(jwks_uri: str, allow_private: bool = False) -> PyJWKClient:
    _check_ssrf(jwks_uri, allow_private)
    cached = _jwks_client_cache.get(jwks_uri)
    now = time.monotonic()
    if cached and (now - cached[1]) < _JWKS_CACHE_TTL_SECONDS:
        return cached[0]
    client = PyJWKClient(
        jwks_uri, cache_keys=True, lifespan=_JWKS_CACHE_TTL_SECONDS, timeout=_HTTP_TIMEOUT
    )
    _jwks_client_cache[jwks_uri] = (client, now)
    return client


def validate_id_token(
    *,
    id_token: str,
    jwks_uri: str,
    issuer_url: str,
    client_id: str,
    nonce: str,
    allow_private: bool = False,
) -> dict:
    """Full OIDC-mandated validation: signature (via JWKS), iss, aud, exp
    (PyJWT enforces exp/iat automatically once given real claims), and
    nonce — not signature-only. Raises OIDCError on any failure; callers
    must treat that as "reject the login", never "log in without this
    check"."""
    try:
        signing_key = _get_jwks_client(jwks_uri, allow_private).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=list(_SUPPORTED_ALGS),
            audience=client_id,
            issuer=issuer_url,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OIDCError(f"id_token validation failed: {exc}") from exc

    token_nonce = claims.get("nonce")
    if not token_nonce or not secrets.compare_digest(str(token_nonce), str(nonce)):
        raise OIDCError("id_token nonce mismatch — possible replay")

    return claims


def fetch_userinfo(
    *, userinfo_endpoint: str, access_token: str, allow_private: bool = False
) -> dict:
    if not userinfo_endpoint:
        return {}
    try:
        resp = _get(
            userinfo_endpoint, allow_private, headers={"Authorization": f"Bearer {access_token}"}
        )
        return resp.json()
    except OIDCError:
        # userinfo is supplementary (id_token is already validated and
        # authoritative for identity) — a userinfo failure shouldn't fail
        # the whole login, just means fewer optional claims are available.
        return {}
