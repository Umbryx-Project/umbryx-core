import asyncio
import os
import uuid
from collections.abc import Awaitable, Callable

from .logging_setup import get_logger

logger = get_logger(__name__)

_INSTANCE_ID = os.environ.get("HOSTNAME", uuid.uuid4().hex[:12])
_LEASE_KEY = "umbryx:leader:"
_LEASE_TTL = 30

# Atomic compare-and-renew: only refresh the TTL if we still own the key.
# A plain GET-then-EXPIRE is two round trips — the key can expire (or be
# claimed by another instance via SET NX) in the window between them, which
# both instances would then believe they own the lease. Doing the compare
# and the renewal inside a single Lua script run by Redis removes that
# window entirely (security audit finding F8).
_RENEW_SCRIPT = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("EXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
"""


async def acquire_lease(role: str, redis_client=None) -> bool:
    """Try to become (or remain) leader for *role*.

    Returns True only when we are confident we hold the lease: either Redis
    is not configured at all (single-instance deployment — there is no one
    to contend with), or we successfully SET NX'd the key, or the atomic
    renew script confirms we still own it. Any Redis error is treated as
    "not leader" (fail-closed) — previously this fail-opened to True, which
    meant a transient Redis outage on one instance let it believe it was
    leader even while a healthy instance elsewhere genuinely held the lease,
    risking the same scheduled action (including offensive playbook steps)
    firing twice.
    """
    if not redis_client:
        return True
    key = f"{_LEASE_KEY}{role}"
    try:
        ok = await redis_client.set(key, _INSTANCE_ID, nx=True, ex=_LEASE_TTL)
        if ok:
            logger.info("Leader lease acquired for %s (instance=%s)", role, _INSTANCE_ID)
            return True
        renewed = await redis_client.eval(_RENEW_SCRIPT, 1, key, _INSTANCE_ID, _LEASE_TTL)
        return bool(renewed)
    except Exception as e:
        logger.warning("Leader election error for %s (treating as not-leader): %s", role, e)
        return False


async def release_lease(role: str, redis_client=None):
    if not redis_client:
        return
    key = f"{_LEASE_KEY}{role}"
    try:
        owner = await redis_client.get(key)
        if owner == _INSTANCE_ID:
            await redis_client.delete(key)
    except Exception:
        pass


async def renewal_loop(
    role: str,
    redis_client=None,
    interval: int = 15,
    on_lost: Callable[[], Awaitable[None] | None] | None = None,
):
    """Keep renewing the lease for *role*. On loss, call *on_lost* (if given)
    so the caller can actually stop the work this instance was doing as
    leader — previously this only logged and returned, leaving the
    now-unprivileged instance's scheduler loop running indefinitely, which
    made the lease mechanism protect only the first ~30-45s after startup."""
    while True:
        await asyncio.sleep(interval)
        acquired = await acquire_lease(role, redis_client)
        if not acquired:
            logger.warning("Lost leader lease for %s", role)
            if on_lost is not None:
                try:
                    result = on_lost()
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    logger.warning("on_lost callback for %s failed: %s", role, e)
            return


def get_redis_client():
    from .token_blacklist import _get_client

    return _get_client()
