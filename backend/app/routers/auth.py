import logging
import os
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.audit import ACT_LOGIN, ACT_LOGOUT, ACT_PASSWORD_CHANGE, log_action
from ..core.config import COOKIE_NAME, COOKIE_SECURE, JWT_EXPIRE_HOURS
from ..core.crypto import decrypt_str, encrypt_str
from ..core.deps import get_current_user
from ..core.enums import UserRole
from ..core.limiter import limiter
from ..core.security import (
    decode_token,
    hash_password,
    make_stream_token,
    make_token,
    token_response,
    verify_password,
)
from ..core.system_log import log_security
from ..core.token_blacklist import blacklist_token, is_blacklisted
from ..core.totp import (
    decode_mfa_pending_token,
    generate_secret,
    make_mfa_pending_token,
    provisioning_uri,
    verify_code,
)
from ..core.utils import new_id, ts_now
from ..database import get_db

_audit = logging.getLogger("app.audit")

router = APIRouter(prefix="/api/auth", tags=["auth"])

_COOKIE_MAX_AGE = JWT_EXPIRE_HOURS * 3600


def _org_enforces_oidc(db: Session, user: models.User) -> bool:
    org_ids = [
        om.org_id
        for om in db.query(models.OrganizationMember).filter(
            models.OrganizationMember.user_id == user.id
        )
    ]
    if not org_ids:
        return False
    return (
        db.query(models.OIDCProvider)
        .filter(
            models.OIDCProvider.org_id.in_(org_ids),
            models.OIDCProvider.enforced,
            models.OIDCProvider.enabled,
        )
        .first()
        is not None
    )


def _set_auth_cookie(response: Response, user: models.User) -> dict:
    token = make_token(user)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        path="/",
        max_age=_COOKIE_MAX_AGE,
    )
    return {
        "user": schemas.UserOut.model_validate(user).model_dump(),
    }


@router.get(
    "/status",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_status(db: Annotated[Session, Depends(get_db)]):
    return {"initialized": db.query(models.User).count() > 0}


@router.post(
    "/setup",
    status_code=201,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
@limiter.limit("5/minute")
def auth_setup(
    body: schemas.SetupRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    if db.query(models.User).count() > 0:
        raise HTTPException(403, "Already initialized — use login")
    # Between airgap install and the first operator login this endpoint is
    # otherwise a first-come-first-served admin takeover on a fresh DB.
    setup_token = os.environ.get("SETUP_TOKEN", "").strip()
    provided = (body.setup_token or "").strip() if hasattr(body, "setup_token") else ""
    if setup_token and not secrets.compare_digest(provided, setup_token):
        raise HTTPException(401, "Invalid setup token")
    from ..core.security import validate_password_strength

    try:
        validate_password_strength(body.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user = models.User(
        id=new_id("u"),
        username=body.username.strip(),
        display_name=body.username.strip(),
        password_hash=hash_password(body.password),
        role=UserRole.PLATFORM_ADMIN.value,
        created_at=ts_now(),
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _set_auth_cookie(response, user)


@router.post(
    "/login",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
@limiter.limit("5/minute")
async def auth_login(
    request: Request,
    body: schemas.LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    user = (
        db.query(models.User)
        .filter(models.User.username == body.username.strip(), models.User.active)
        .first()
    )
    ip = request.client.host if request.client else "unknown"

    if user and user.role != UserRole.PLATFORM_ADMIN.value and _org_enforces_oidc(db, user):
        # "Obligatory OIDC" (routers/oidc_admin.py) — password login is
        # refused for this org's members once an admin has enabled it
        # (only possible after a verified successful OIDC round trip, so
        # this can't be flipped on by a broken config and brick everyone
        # at once). platform_admin is exempt so the bootstrap account can
        # never be locked out of its own platform by an org-level toggle.
        raise HTTPException(
            403, "Password login is disabled for this account — sign in with SSO instead"
        )

    if user:
        from ..core.token_blacklist import _get_client as _get_redis

        _redis = _get_redis()
        if _redis:
            _lock_key = f"lockout:{user.id}"
            try:
                locked = await _redis.get(_lock_key)
                if locked and int(locked) >= 10:
                    _audit.warning("AUTH account_locked user=%s ip=%s", user.username, ip)
                    raise HTTPException(
                        429,
                        "Account temporarily locked due to too many failed attempts. Try again later.",
                    )
            except HTTPException:
                raise
            except Exception as e:
                # Brute-force lockout is disabled for this login attempt —
                # make that visible instead of silently degrading (F24).
                _audit.warning(
                    "AUTH lockout_check_failed user=%s ip=%s error=%s", user.username, ip, e
                )

    # Always run verify_password, even for a nonexistent user (passing
    # None rather than short-circuiting on `not user`) — see verify_password's
    # docstring: skipping the bcrypt call for a missing user made that case
    # ~40x faster than a wrong password against a real account, a timing
    # side-channel for username enumeration (security retest, 2026-09-03).
    password_ok = verify_password(body.password, user.password_hash if user else None)
    if not user or not password_ok:
        _audit.warning("AUTH login_failed username=%s ip=%s", body.username.strip(), ip)
        log_security(
            db,
            "auth.failed",
            ip=ip,
            success=False,
            message=f"login_failed username={body.username.strip()}",
        )

        if user:
            from ..core.token_blacklist import _get_client as _get_redis

            _redis = _get_redis()
            if _redis:
                try:
                    _lock_key = f"lockout:{user.id}"
                    fails = await _redis.incr(_lock_key)
                    await _redis.expire(_lock_key, 900)
                    if fails >= 10:
                        await _redis.setex(_lock_key, 1800, str(fails))
                except Exception as e:
                    # Failed-attempt counter didn't get recorded — brute-force
                    # protection is silently degraded for this account until
                    # Redis recovers; make that visible instead (F24).
                    _audit.warning(
                        "AUTH lockout_record_failed user=%s ip=%s error=%s", user.username, ip, e
                    )

        raise HTTPException(401, "Invalid username or password")

    from ..core.token_blacklist import _get_client as _get_redis

    _redis = _get_redis()
    if _redis:
        try:
            await _redis.delete(f"lockout:{user.id}")
        except Exception:
            pass
    if user.mfa_enabled and user.totp_secret:
        _audit.info("AUTH login_mfa_required user=%s ip=%s", user.username, ip)
        log_security(
            db,
            "auth.mfa_required",
            user_id=user.id,
            ip=ip,
            success=True,
            message=f"mfa_required user={user.username}",
        )
        return {"mfa_required": True, "mfa_token": make_mfa_pending_token(user.id)}
    _audit.info("AUTH login user=%s ip=%s", user.username, ip)
    log_security(
        db,
        "auth.login",
        user_id=user.id,
        ip=ip,
        success=True,
        message=f"login user={user.username}",
    )
    log_action(db, action=ACT_LOGIN, actor_id=user.id, actor_name=user.username, ip_address=ip)
    return _set_auth_cookie(response, user)


@router.post(
    "/mfa/verify",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
@limiter.limit("10/minute")
def auth_mfa_verify(
    request: Request,
    body: schemas.MfaVerifyRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    user_id = decode_mfa_pending_token(body.mfa_token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired MFA token")
    user = db.query(models.User).filter(models.User.id == user_id, models.User.active).first()
    if not user or not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(401, "MFA not configured for this account")
    secret = decrypt_str(user.totp_secret)
    if not verify_code(secret, body.code.strip()):
        ip = request.client.host if request.client else "unknown"
        _audit.warning("AUTH mfa_failed user=%s ip=%s", user.username, ip)
        raise HTTPException(401, "Invalid TOTP code")
    ip = request.client.host if request.client else "unknown"
    _audit.info("AUTH login user=%s ip=%s (mfa)", user.username, ip)
    return _set_auth_cookie(response, user)


@router.post(
    "/mfa/setup",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_mfa_setup(
    user: Annotated[models.User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]
):
    """Generate a new TOTP secret and return the provisioning URI. Does not enable MFA yet."""
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled. Disable it first.")
    secret = generate_secret()
    uri = provisioning_uri(secret, user.username)
    # Store encrypted pending secret (not yet enabled until verify)
    db_user = db.query(models.User).filter(models.User.id == user.id).first()
    db_user.totp_secret = encrypt_str(secret)
    db.commit()
    return {"uri": uri, "secret": secret}


@router.post(
    "/mfa/enable",
    status_code=204,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_mfa_enable(
    body: schemas.MfaEnableRequest,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Confirm TOTP code and activate MFA on the account."""
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled")
    db_user = db.query(models.User).filter(models.User.id == user.id).first()
    if not db_user.totp_secret:
        raise HTTPException(400, "Call /mfa/setup first")
    secret = decrypt_str(db_user.totp_secret)
    if not verify_code(secret, body.code.strip()):
        raise HTTPException(400, "Invalid TOTP code — check your authenticator app")
    db_user.mfa_enabled = True
    db.commit()
    _audit.info("AUTH mfa_enabled user=%s", user.username)


@router.post(
    "/mfa/disable",
    status_code=204,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_mfa_disable(
    body: schemas.MfaDisableRequest,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Verify TOTP code and disable MFA."""
    if not user.mfa_enabled:
        raise HTTPException(400, "MFA is not enabled")
    db_user = db.query(models.User).filter(models.User.id == user.id).first()
    secret = decrypt_str(db_user.totp_secret)
    if not verify_code(secret, body.code.strip()):
        raise HTTPException(400, "Invalid TOTP code")
    db_user.mfa_enabled = False
    db_user.totp_secret = None
    db.commit()
    _audit.info("AUTH mfa_disabled user=%s", user.username)


@router.post(
    "/logout",
    status_code=204,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
async def auth_logout(
    request: Request,
    response: Response,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    ip = request.client.host if request.client else "unknown"
    _audit.info("AUTH logout user=%s ip=%s", user.username, ip)
    log_action(db, action=ACT_LOGOUT, actor_id=user.id, actor_name=user.username, ip_address=ip)
    response.delete_cookie(key=COOKIE_NAME, path="/", samesite="strict")
    # Revoke the token so it cannot be replayed before natural expiry.
    raw = request.cookies.get(COOKIE_NAME, "")
    if not raw:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            raw = auth_hdr[7:]
    if raw:
        payload = decode_token(raw)
        if payload and payload.get("jti") and payload.get("exp"):
            await blacklist_token(payload["jti"], int(payload["exp"]))


@router.get(
    "/me",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_me(user: Annotated[models.User, Depends(get_current_user)]):
    return schemas.UserOut.model_validate(user)


@router.post("/refresh")
async def auth_refresh(
    body: dict,
    db: Annotated[Session, Depends(get_db)],
):
    refresh_token = body.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(401, "Missing refresh token")
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(401, "Invalid refresh token")
    if await is_blacklisted(payload.get("jti", "")):
        raise HTTPException(401, "Refresh token has been revoked")
    db_user = (
        db.query(models.User).filter(models.User.id == payload["sub"], models.User.active).first()
    )
    if not db_user:
        raise HTTPException(401, "User not found")
    # Rotation: revoke the presented refresh token the moment a new pair is
    # issued — a stolen token dies on first (legit or attacker) use instead
    # of living until exp.
    if payload.get("jti") and payload.get("exp"):
        await blacklist_token(payload["jti"], int(payload["exp"]))
    return token_response(db_user)


@router.post("/stream-token")
@limiter.limit("30/minute")
def auth_stream_token(
    request: Request,
    user: Annotated[models.User, Depends(get_current_user)],
):
    # Was importing from a module that doesn't exist (`..core.auth`) —
    # 500 on every call, silently breaking SSE/EventSource auth for any
    # caller that needs a ?token= (security retest, 2026-09-03).
    return {"token": make_stream_token(user)}


@router.patch(
    "/me",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_update_me(
    body: schemas.UpdateProfileRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    display_name = body.display_name.strip()
    if not display_name:
        raise HTTPException(400, "Display name cannot be empty")

    db_user = db.query(models.User).filter(models.User.id == user.id, models.User.active).first()
    if not db_user:
        raise HTTPException(404, "User not found")

    db_user.display_name = display_name
    if body.email is not None:
        email_norm = body.email.strip().lower() or None
        if email_norm and (
            db.query(models.User)
            .filter(models.User.email == email_norm, models.User.id != user.id)
            .first()
        ):
            raise HTTPException(409, "Email is already in use by another account")
        db_user.email = email_norm
    db.commit()
    db.refresh(db_user)
    return schemas.UserOut.model_validate(db_user)


@router.post(
    "/change-password",
    status_code=204,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def auth_change_password(
    body: schemas.ChangePasswordRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    from ..core.security import validate_password_strength

    try:
        validate_password_strength(body.new_password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if body.current_password == body.new_password:
        raise HTTPException(400, "New password must be different from the current password")

    db_user = db.query(models.User).filter(models.User.id == user.id, models.User.active).first()
    if not db_user:
        raise HTTPException(404, "User not found")

    db_user.password_hash = hash_password(body.new_password)
    db.commit()
    _audit.info("AUTH password_changed user=%s", user.username)
    log_action(db, action=ACT_PASSWORD_CHANGE, actor_id=user.id, actor_name=user.username)
