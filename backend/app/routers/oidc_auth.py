"""
Public OIDC/SSO authentication endpoints — the browser-facing half of the
flow (org-scoped provider admin lives in routers/oidc_admin.py).

Design note on the F1 class of bug (MFA bypass via a stage-1 token reused
as a stage-2 token): every intermediate state in this flow is carried by a
JWT with an explicit `type` claim that every other decoder in the app
rejects (core/security.py::decode_access_token already only accepts
type in (None, "access")) — `oidc_auth_states.state` never leaves the
server at all (it's a DB row keyed by the opaque `state` query param, not
a token), the MFA step reuses core/totp.py's existing mfa_pending token
verbatim, and the account-link step uses its own single-purpose
oidc_link_pending token (core/oidc/link_token.py). None of these three
can be presented to get_current_user / any authenticated endpoint — only
/api/auth/mfa/verify and /api/auth/oidc/confirm-link know how to consume
them, and both require additional proof (a valid TOTP code; the target
account's actual password) before minting a real session token.
"""

import logging
import secrets
from datetime import timedelta
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.audit import (
    ACT_OIDC_ACCOUNT_LINKED,
    ACT_OIDC_JIT_PROVISIONED,
    ACT_OIDC_LOGIN_FAILED,
    ACT_OIDC_LOGIN_SUCCESS,
    log_action,
)
from ..core.config import COOKIE_SECURE, PUBLIC_BASE_URL
from ..core.crypto import decrypt_str
from ..core.limiter import limiter
from ..core.oidc.client import (
    OIDCError,
    build_authorization_url,
    exchange_code,
    generate_pkce_pair,
    validate_id_token,
)
from ..core.oidc.flow import (
    create_identity,
    find_existing_identity,
    find_user_by_email,
    jit_provision_user,
    resolve_claim,
)
from ..core.oidc.link_token import decode_link_pending_token, make_link_pending_token
from ..core.plan import PlanFeature, has_feature, instance_has_feature
from ..core.security import verify_password
from ..core.system_log import log_security
from ..core.totp import make_mfa_pending_token
from ..core.utils import ts_now, utcnow
from ..database import get_db
from .auth import _set_auth_cookie

logger = logging.getLogger(__name__)
_audit = logging.getLogger("app.audit")

router = APIRouter(prefix="/api/auth/oidc", tags=["oidc"])

_STATE_TTL_SECONDS = 600
# Login-CSRF / session-fixation guard: the `state` DB row alone proves a
# flow was legitimately initiated by *someone*, but not that the browser
# completing /callback is the same one that started it at /login — an
# attacker can run the whole flow themselves, capture their own valid
# state+code, and hand the callback URL to a victim, whose browser would
# otherwise complete a login into a session the attacker controls. Binding
# state to a same-site, HttpOnly cookie set at initiation time closes
# that: only the initiating browser carries the cookie /callback checks
# against.
_STATE_COOKIE = "oidc_state"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _redirect_uri(request: Request, provider_id: str) -> str:
    base = PUBLIC_BASE_URL or str(request.base_url).rstrip("/")
    return f"{base}/api/auth/oidc/{provider_id}/callback"


def _safe_redirect_after(value: str | None) -> str:
    """Only a same-origin relative path is ever honored — never a
    scheme-relative ("//evil.com") or absolute URL from a query param."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


def _frontend_redirect(fragment: str) -> RedirectResponse:
    base = PUBLIC_BASE_URL or "/"
    return RedirectResponse(url=f"{base}#{fragment}", status_code=302)


def _get_enabled_provider(db: Session, provider_id: str) -> models.OIDCProvider:
    provider = (
        db.query(models.OIDCProvider)
        .filter(models.OIDCProvider.id == provider_id, models.OIDCProvider.enabled)
        .first()
    )
    if not provider:
        raise HTTPException(404, "OIDC provider not found or disabled")
    # Plan gate on the flow itself: a provider created under an SSO tier
    # keeps its row when the plan lapses, but must stop authenticating —
    # org-scoped providers check the org plan, platform-wide ones the
    # instance entitlement (same rule the admin routers enforce on write).
    if provider.org_id:
        entitled = has_feature(provider.org_id, PlanFeature.SSO, db)
    else:
        entitled = instance_has_feature(PlanFeature.SSO, db)
    if not entitled:
        raise HTTPException(403, "SSO/OIDC requires a higher plan tier. Contact your administrator.")
    return provider


def _sso_entitled(db: Session, provider: models.OIDCProvider) -> bool:
    """Same plan gate as _get_enabled_provider, for filtering the public
    provider list: a lapsed plan should drop the IdP off the login page,
    not offer a button that 403s on click."""
    if provider.org_id:
        return has_feature(provider.org_id, PlanFeature.SSO, db)
    return instance_has_feature(PlanFeature.SSO, db)


@router.get("/providers")
def list_public_oidc_providers(
    db: Annotated[Session, Depends(get_db)],
    email: str | None = None,
    org_slug: str | None = None,
):
    """Unauthenticated — but never dumps the whole provider list: the
    caller must narrow by an email domain or an explicit org slug, so this
    can't be used to enumerate every organization's IdP on the platform.

    Two conveniences on top of the domain match:
    * a value without "@" is treated as a username — the user's stored
      email supplies the domain (login-by-login instead of login-by-email);
    * called with no email and no org_slug at all, only platform-wide
      CATCH-ALL providers (empty email_domain, org_id NULL) are listed —
      those are deliberately "any address on this instance", so showing
      them up front on the login page is the intended UX, not enumeration.
    """
    typed = bool((email or "").strip())
    if email and "@" not in email:
        user = (
            db.query(models.User).filter(models.User.username == email.strip()).first()
        )
        email = user.email if user and user.email else None
    org_q = (
        db.query(models.OIDCProvider, models.Organization)
        .join(models.Organization, models.OIDCProvider.org_id == models.Organization.id)
        .filter(models.OIDCProvider.enabled)
    )
    # Platform-wide providers (org_id IS NULL) have no Organization row to
    # join — a separate query, unioned below, rather than an outer join
    # that would need every downstream column reference to handle a NULL
    # Organization.
    platform_q = db.query(models.OIDCProvider).filter(
        models.OIDCProvider.enabled, models.OIDCProvider.org_id.is_(None)
    )

    results: list[dict] = []
    if org_slug:
        for p, o in org_q.filter(models.Organization.slug == org_slug).all():
            if not _sso_entitled(db, p):
                continue
            results.append(
                {"id": p.id, "name": p.name, "org_name": o.name, "org_slug": o.slug, "enforced": p.enforced}
            )
        return results

    if email and "@" in email:
        domain = email.rsplit("@", 1)[-1].strip().lower()
        if not domain:
            return []
        # An org-scoped provider with an empty email_domain is a catch-all
        # for that organization — match it for any domain, same as the
        # platform-wide catch-alls below.
        for p, o in org_q.filter(
            (models.OIDCProvider.email_domain == domain) | (models.OIDCProvider.email_domain == "")
        ).all():
            if not _sso_entitled(db, p):
                continue
            results.append(
                {"id": p.id, "name": p.name, "org_name": o.name, "org_slug": o.slug, "enforced": p.enforced}
            )
        # A platform-wide provider with no email_domain configured is a
        # deliberate catch-all ("our whole company, any address") — one
        # with a domain set still only matches that domain, same as the
        # org-scoped case above.
        for p in platform_q.filter(
            (models.OIDCProvider.email_domain == domain) | (models.OIDCProvider.email_domain == "")
        ).all():
            if not _sso_entitled(db, p):
                continue
            results.append(
                {"id": p.id, "name": p.name, "org_name": None, "org_slug": None, "enforced": p.enforced}
            )
        return results

    # No narrowing at all: only platform-wide catch-alls, up front.
    for p in platform_q.filter(models.OIDCProvider.email_domain == "").all():
        if not _sso_entitled(db, p):
            continue
        results.append(
            {"id": p.id, "name": p.name, "org_name": None, "org_slug": None, "enforced": p.enforced}
        )
    # A login was typed but mapped to no email (unknown username, or a
    # local account without one) — org-scoped catch-alls are still a
    # valid destination, list them too.
    if typed:
        for p, o in org_q.filter(models.OIDCProvider.email_domain == "").all():
            if not _sso_entitled(db, p):
                continue
            results.append(
                {"id": p.id, "name": p.name, "org_name": o.name, "org_slug": o.slug, "enforced": p.enforced}
            )
    return results


@router.get("/{provider_id}/login")
@limiter.limit("20/minute")
def oidc_login_initiate(
    request: Request,
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    redirect_after: str | None = None,
):
    provider = _get_enabled_provider(db, provider_id)
    if not provider.authorization_endpoint:
        raise HTTPException(400, "Provider is not fully configured (missing discovery data)")

    # Lazy cleanup of dead state rows — no periodic job needed for what's
    # a handful of short-lived rows per login attempt. expires_at is the
    # same ISO-8601-with-Z string shape as every other *_at column in this
    # codebase (ts_now()) specifically so plain string comparison sorts
    # correctly, same as everywhere else that compares timestamps this way.
    db.query(models.OIDCAuthState).filter(models.OIDCAuthState.expires_at < ts_now()).delete(
        synchronize_session=False
    )

    # secrets.token_urlsafe rather than new_id() here — state/nonce are
    # security tokens (CSRF / replay defenses), not entity ids, and
    # new_id()'s 8 hex chars (32 bits) is fine for a row key but thin for
    # something an attacker might want to guess or brute-force offline.
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()

    db.add(
        models.OIDCAuthState(
            state=state,
            provider_id=provider.id,
            code_verifier=code_verifier,
            nonce=nonce,
            redirect_after=_safe_redirect_after(redirect_after),
            created_at=ts_now(),
            expires_at=(utcnow() + timedelta(seconds=_STATE_TTL_SECONDS)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        )
    )
    db.commit()

    auth_url = build_authorization_url(
        authorization_endpoint=provider.authorization_endpoint,
        client_id=provider.client_id,
        redirect_uri=_redirect_uri(request, provider.id),
        scopes=provider.scopes or ["openid", "email", "profile"],
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        allow_private=provider.allow_private_issuer,
    )
    resp = RedirectResponse(url=auth_url, status_code=302)
    # Login-CSRF/session-fixation guard — see _STATE_COOKIE comment above.
    resp.set_cookie(
        key=_STATE_COOKIE,
        value=state,
        httponly=True,
        samesite="lax",  # "lax" (not "strict") — this cookie must still be
        # sent on the top-level GET navigation back from the IdP, which is
        # a cross-site navigation from the browser's perspective.
        secure=COOKIE_SECURE,
        path="/api/auth/oidc",
        max_age=_STATE_TTL_SECONDS,
    )
    return resp


def _fail(db: Session, provider_id: str, ip: str, reason: str, log_reason: str) -> RedirectResponse:
    _audit.warning("OIDC login_failed provider=%s ip=%s reason=%s", provider_id, ip, log_reason)
    log_security(
        db, "oidc.failed", ip=ip, success=False, message=f"oidc_login_failed: {log_reason}"
    )
    log_action(
        db,
        action=ACT_OIDC_LOGIN_FAILED,
        target_type="oidc_provider",
        target_id=provider_id,
        detail={"reason": log_reason},
        ip_address=ip,
    )
    db.commit()
    return _frontend_redirect(f"oidc_error={quote(reason)}")


@router.get("/{provider_id}/callback")
@limiter.limit("20/minute")
def oidc_callback(
    request: Request,
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    # Every exit from _oidc_callback_body is a Response object (never a
    # plain dict FastAPI would serialize itself), so a single wrap here —
    # rather than repeating .delete_cookie() at each of that function's
    # several return sites — reliably clears the single-use state cookie
    # on every path: success, every _fail() branch, all of them.
    resp = _oidc_callback_body(request, provider_id, db, code=code, state=state, error=error)
    resp.delete_cookie(_STATE_COOKIE, path="/api/auth/oidc")
    return resp


def _oidc_callback_body(
    request: Request,
    provider_id: str,
    db: Session,
    *,
    code: str | None,
    state: str | None,
    error: str | None,
):
    ip = _client_ip(request)
    provider = _get_enabled_provider(db, provider_id)

    if error:
        return _fail(
            db,
            provider_id,
            ip,
            "Login was cancelled or rejected by the identity provider",
            f"idp_error:{error}",
        )
    if not code or not state:
        return _fail(db, provider_id, ip, "Invalid OIDC response", "missing_code_or_state")

    # Login-CSRF / session-fixation guard (see _STATE_COOKIE above): the
    # browser completing this callback must be the same one /login set the
    # cookie on. Checked before the DB lookup so an attacker who merely
    # captured/guessed a valid `state` value — without ever having driven
    # this browser through /login — can't get any further, regardless of
    # whether the state row itself is still valid.
    cookie_state = request.cookies.get(_STATE_COOKIE)
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        return _fail(db, provider_id, ip, "Invalid OIDC response", "state_cookie_mismatch")

    # `state` is looked up (never trusted from anywhere else), single-use —
    # deleted immediately whether or not the rest of the flow succeeds, so
    # a captured/replayed callback URL can never be completed twice.
    state_row = db.query(models.OIDCAuthState).filter(models.OIDCAuthState.state == state).first()
    if state_row:
        db.delete(state_row)
        db.commit()
    if not state_row or state_row.provider_id != provider.id:
        return _fail(
            db,
            provider_id,
            ip,
            "Login session expired or invalid — please try again",
            "state_not_found_or_mismatched",
        )
    if state_row.expires_at < ts_now():
        return _fail(
            db, provider_id, ip, "Login session expired — please try again", "state_expired"
        )

    try:
        tokens = exchange_code(
            token_endpoint=provider.token_endpoint,
            client_id=provider.client_id,
            client_secret=decrypt_str(provider.client_secret),
            code=code,
            redirect_uri=_redirect_uri(request, provider.id),
            code_verifier=state_row.code_verifier,
            allow_private=provider.allow_private_issuer,
        )
        claims = validate_id_token(
            id_token=tokens["id_token"],
            jwks_uri=provider.jwks_uri,
            issuer_url=provider.issuer_url,
            client_id=provider.client_id,
            nonce=state_row.nonce,
            allow_private=provider.allow_private_issuer,
        )
    except OIDCError as exc:
        return _fail(db, provider_id, ip, "Sign-in with your identity provider failed", str(exc))

    subject = claims.get("sub", "")
    if not subject:
        return _fail(
            db, provider_id, ip, "Identity provider did not return a subject claim", "missing_sub"
        )
    email = resolve_claim(provider.claim_mapping, claims, "email", "email").strip().lower()
    name = resolve_claim(provider.claim_mapping, claims, "name", "name")

    # 1) Already-linked identity — the common case on every login after the first.
    existing = find_existing_identity(db, provider.id, subject)
    if existing:
        user = (
            db.query(models.User)
            .filter(models.User.id == existing.user_id, models.User.active)
            .first()
        )
        if not user:
            return _fail(
                db, provider_id, ip, "Linked account is no longer active", "linked_user_inactive"
            )
        return _finish_login(db, provider, user, ip, redirect_after=state_row.redirect_after)

    # 2) No link yet, but an active platform account already uses this
    # email — never auto-link (account-takeover guard): a colliding/
    # spoofed email at a less-trusted IdP must not silently absorb an
    # existing password-based account. Hand back a short-lived,
    # single-purpose token that /confirm-link additionally requires that
    # account's real password to redeem.
    matched = find_user_by_email(db, email) if email else None
    if matched:
        link_token = make_link_pending_token(
            matched_user_id=matched.id, provider_id=provider.id, subject=subject, email=email
        )
        _audit.info("OIDC link_required provider=%s email=%s ip=%s", provider_id, email, ip)
        return _frontend_redirect(f"oidc_link={quote(link_token)}")

    # 3) No match at all — JIT-provision if the org allows it, else reject.
    if not provider.jit_provisioning_enabled:
        return _fail(
            db,
            provider_id,
            ip,
            "No account found for this identity and the organization does not allow self-signup",
            "no_match_jit_disabled",
        )
    user = jit_provision_user(db, provider=provider, email=email, name=name, claims=claims)
    create_identity(db, provider_id=provider.id, subject=subject, user_id=user.id, email=email)
    log_action(
        db,
        action=ACT_OIDC_JIT_PROVISIONED,
        actor_id=user.id,
        actor_name=user.username,
        target_type="user",
        target_id=user.id,
        detail={"provider_id": provider.id, "org_id": provider.org_id, "email": email},
        ip_address=ip,
    )
    db.commit()
    return _finish_login(db, provider, user, ip, redirect_after=state_row.redirect_after)


class ConfirmLinkBody(BaseModel):
    link_token: str
    username: str
    password: str


@router.post("/confirm-link")
@limiter.limit("10/minute")
def oidc_confirm_link(
    request: Request,
    body: ConfirmLinkBody,
    db: Annotated[Session, Depends(get_db)],
):
    """Redeems an oidc_link_pending token — requires the target account's
    real password, not just possession of the token, which is what
    actually prevents an attacker who merely controls a same/similar email
    at some IdP from taking over an existing platform account."""
    ip = _client_ip(request)
    payload = decode_link_pending_token(body.link_token)
    if not payload:
        raise HTTPException(401, "Invalid or expired link confirmation")

    user = (
        db.query(models.User)
        .filter(
            models.User.id == payload["matched_user_id"],
            models.User.username == body.username.strip(),
            models.User.active,
        )
        .first()
    )
    # Same timing-parity fix as auth.py's login handler: always run
    # verify_password rather than short-circuiting on `not user`.
    password_ok = verify_password(body.password, user.password_hash if user else None)
    if not user or not password_ok:
        _audit.warning("OIDC link_confirm_failed user=%s ip=%s", body.username.strip(), ip)
        log_security(db, "oidc.link_confirm_failed", ip=ip, success=False)
        db.commit()
        raise HTTPException(401, "Incorrect username or password")

    provider = (
        db.query(models.OIDCProvider)
        .filter(models.OIDCProvider.id == payload["provider_id"])
        .first()
    )
    if not provider or not provider.enabled:
        raise HTTPException(400, "OIDC provider is no longer available")

    create_identity(
        db,
        provider_id=provider.id,
        subject=payload["subject"],
        user_id=user.id,
        email=payload["email"],
    )
    log_action(
        db,
        action=ACT_OIDC_ACCOUNT_LINKED,
        actor_id=user.id,
        actor_name=user.username,
        target_type="user",
        target_id=user.id,
        detail={"provider_id": provider.id, "email": payload["email"]},
        ip_address=ip,
    )
    db.commit()
    return _finish_login(db, provider, user, ip, redirect_after="/", as_json=True)


def _finish_login(
    db: Session,
    provider: models.OIDCProvider,
    user: models.User,
    ip: str,
    *,
    redirect_after: str,
    as_json: bool = False,
):
    """Shared tail for every successful-identity path (linked, JIT, and
    confirm-link) — same MFA-gate decision, same audit trail. `as_json` is
    used only by confirm-link, which is called via fetch() from the SPA
    (not a browser navigation), so it gets a normal JSON response with the
    cookie set on it, same shape as POST /api/auth/login."""
    provider.last_test_login_at = ts_now()
    db.commit()

    if provider.require_platform_mfa and user.mfa_enabled and user.totp_secret:
        # Identical to the password-login MFA branch (routers/auth.py) —
        # no cookie, no access token, just the same short-lived
        # mfa_pending token. The OIDC id_token being valid is not, by
        # itself, treated as "logged in" any more than a correct password
        # is on its own — this is the exact property that was missing for
        # F1 and is what must hold here too.
        mfa_token = make_mfa_pending_token(user.id)
        log_security(db, "oidc.mfa_required", user_id=user.id, ip=ip, success=True)
        db.commit()
        if as_json:
            return {"mfa_required": True, "mfa_token": mfa_token}
        return _frontend_redirect(f"oidc_mfa={quote(mfa_token)}")

    _audit.info("OIDC login user=%s provider=%s ip=%s", user.username, provider.id, ip)
    log_security(
        db,
        "oidc.login",
        user_id=user.id,
        ip=ip,
        success=True,
        message=f"oidc_login user={user.username}",
    )
    log_action(
        db,
        action=ACT_OIDC_LOGIN_SUCCESS,
        actor_id=user.id,
        actor_name=user.username,
        target_type="oidc_provider",
        target_id=provider.id,
        ip_address=ip,
    )
    db.commit()

    if as_json:
        cookie_carrier = Response()
        result = _set_auth_cookie(cookie_carrier, user)
        json_resp = JSONResponse(content=result)
        for key, value in cookie_carrier.raw_headers:
            if key == b"set-cookie":
                json_resp.raw_headers.append((key, value))
        return json_resp

    dest = _safe_redirect_after(redirect_after)
    resp = RedirectResponse(url=dest, status_code=302)
    _set_auth_cookie(resp, user)
    return resp
