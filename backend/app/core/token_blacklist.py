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
