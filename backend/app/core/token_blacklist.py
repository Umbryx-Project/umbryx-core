"""
JWT revocation via Redis.

On logout the token's `jti` claim is stored with a TTL equal to the
remaining token lifetime.  The auth middleware checks this before
admitting the request.  If Redis is unreachable the check is skipped
(fail-open): tokens still expire naturally at their `exp` time.
"""

import logging
import os
from datetime import UTC, datetime

from .redis_factory import create_redis_connection_decode

_REDIS_URL = os.environ.get("REDIS_URL", "")
_logger = logging.getLogger(__name__)

_KEY_PREFIX = "jwt:bl:"
_FAIL_CLOSED = os.environ.get("JWT_BLACKLIST_FAIL_CLOSED", "true").lower() in ("1", "true", "yes")
_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    if not _REDIS_URL:
        return None
    try:
        _client = create_redis_connection_decode()
        return _client
    except Exception as exc:
        _logger.warning("token_blacklist: Redis unavailable: %s", exc)
        return None


async def blacklist_token(jti: str, exp: int) -> None:
    """Revoke *jti* until its natural expiry at Unix timestamp *exp*."""
    client = _get_client()
    if not client:
        return
    try:
        ttl = max(1, exp - int(datetime.now(UTC).timestamp()))
        await client.setex(f"{_KEY_PREFIX}{jti}", ttl, "1")
    except Exception as exc:
        _logger.warning("token_blacklist: could not revoke jti=%s: %s", jti, exc)


def _get_sync_client():
    """Sync Redis client for revocation checks outside async request flow."""
    try:
        from .redis_factory import create_redis_sync

        return create_redis_sync()
    except Exception as exc:
        _logger.warning("token_blacklist: sync redis unavailable: %s", exc)
        return None


def blacklist_token_sync(jti: str, exp: int) -> None:
    """Sync flavour of blacklist_token (AUTH-04 single-use MFA tokens)."""
    if not jti:
        return
    client = _get_sync_client()
    if client is None:
        return
    try:
        ttl = max(1, exp - int(datetime.now(UTC).timestamp()))
        client.setex(f"{_KEY_PREFIX}{jti}", ttl, "1")
    except Exception as exc:
        _logger.warning("token_blacklist: could not revoke jti=%s: %s", jti, exc)


def _redis_configured() -> bool:
    """True when the deployment EXPLICITLY configured Redis.

    redis_factory defaults to localhost:6379 when REDIS_URL is unset —
    in the test container that means a client object that can never
    connect. Distinguish 'not configured' (no blacklist exists, pass)
    from 'configured but unreachable' (fail closed, re-review 2026-11-02).
    """
    import os

    return bool(
        os.environ.get("REDIS_URL", "").strip()
        or os.environ.get("REDIS_SENTINEL_HOSTS", "").strip()
    )


def is_blacklisted_sync(jti: str) -> bool:
    """Sync flavour of is_blacklisted, fail-closed like its async twin.

    Re-review 2026-11-02 (F18): both used to fail OPEN on a Redis error,
    contradicting the module's own documented policy. An unperformable
    revocation check is a FAILED check — but only when Redis was
    actually configured (test containers without Redis legitimately pass).
    """
    if not jti:
        return False
    if not _redis_configured():
        return False  # no Redis configured = nothing was ever revoked
    client = _get_sync_client()
    if client is None:
        return False
    try:
        return bool(client.get(f"{_KEY_PREFIX}{jti}"))
    except Exception as exc:
        _logger.warning("token_blacklist: sync check FAILED CLOSED for %s: %s", jti, exc)
        return True


async def revoke_all_user_sessions(user_id: str) -> None:
    """AUTH-05 fix (Shannon 2026-10-29): reject every token issued BEFORE
    now for this user — fired on password change and admin reset so a
    stolen/leaked session dies with the credential rotation. TTL covers the
    maximum access-token lifetime, after which every token has expired
    naturally anyway."""
    client = _get_client()
    if not client:
        return
    try:
        from ..core.config import JWT_EXPIRE_HOURS

        ttl = JWT_EXPIRE_HOURS * 3600 + 300
        await client.setex(
            f"{_KEY_PREFIX}user-revoked:{user_id}", ttl, str(int(datetime.now(UTC).timestamp()))
        )
    except Exception as exc:
        _logger.warning("token_blacklist: could not revoke sessions for %s: %s", user_id, exc)


async def user_sessions_revoked(user_id: str, iat: int) -> bool:
    """True if all of user_id's tokens issued before *iat* were revoked."""
    if not user_id or not iat:
        return False
    client = _get_client()
    if not client:
        return False
    try:
        ts = await client.get(f"{_KEY_PREFIX}user-revoked:{user_id}")
        return bool(ts and int(ts) > int(iat))
    except Exception as exc:
        # Re-review 2026-11-02 (F18 consistency): a Redis outage used to
        # fail OPEN — revoked-after-password-change sessions kept working.
        # Fail CLOSED: a check we cannot perform is a check we treat as
        # failed. Sessions recover automatically once Redis is back.
        _logger.warning(
            "token_blacklist: revocation check FAILED CLOSED for %s: %s", user_id, exc
        )
        return True


async def is_blacklisted(jti: str) -> bool:
    """Return True if *jti* has been explicitly revoked."""
    if not jti:
        return False
    client = _get_client()
    if not client:
        if not _REDIS_URL:
            # Redis was never configured for this deployment at all — token
            # revocation is a deliberately-disabled feature here (matches
            # e.g. leader_election's "no Redis configured -> no contention
            # to guard against" convention), not an outage. Failing closed
            # here would reject every login on any Redis-less deployment.
            return False
        # Redis IS configured but the client failed to connect — an actual
        # outage of a feature that should be working. Previously this
        # unconditionally returned False here too (fail-open: every token
        # treated as never-revoked) regardless of JWT_BLACKLIST_FAIL_CLOSED,
        # inconsistent with the per-call exception path below (security
        # audit finding F18).
        return _FAIL_CLOSED
    try:
        return bool(await client.exists(f"{_KEY_PREFIX}{jti}"))
    except Exception:
        return _FAIL_CLOSED
