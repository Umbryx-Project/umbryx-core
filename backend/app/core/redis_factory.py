"""
Redis connection factory with Sentinel HA support.

Configure via environment variables:
  REDIS_URL            - Single instance (default: redis://localhost:6379/0)
  REDIS_SENTINEL_HOSTS - Comma-separated sentinel addresses (host:port,host:port)
  REDIS_SENTINEL_MASTER - Master name (default: mymaster)
  REDIS_SENTINEL_PASSWORD - Sentinel password (optional)
  REDIS_PASSWORD       - Redis instance password (optional)
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def _parse_sentinel_hosts(raw: str) -> list[tuple[str, int]]:
    """Parse 'host1:26379,host2:26379,host3:26379' into list of tuples."""
    result = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            host, port_str = part.rsplit(":", 1)
            result.append((host, int(port_str)))
        else:
            result.append((part, 26379))
    return result


def create_redis_connection():
    """Create a Redis connection (or Sentinel-aware connection)."""
    import redis.asyncio as aioredis

    sentinel_hosts_env = os.environ.get("REDIS_SENTINEL_HOSTS", "")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    redis_password = os.environ.get("REDIS_PASSWORD")

    if sentinel_hosts_env:
        try:
            from redis.asyncio.sentinel import Sentinel

            hosts = _parse_sentinel_hosts(sentinel_hosts_env)
            master_name = os.environ.get("REDIS_SENTINEL_MASTER", "mymaster")
            sentinel_password = os.environ.get("REDIS_SENTINEL_PASSWORD")

            kwargs = {}
            if sentinel_password:
                kwargs["sentinel_kwargs"] = {"password": sentinel_password}
            if redis_password:
                kwargs["password"] = redis_password

            sentinel = Sentinel(hosts, **kwargs)
            conn = sentinel.master_for(master_name)
            logger.info(
                "[redis] Connected via Sentinel to master '%s' (%s)",
                master_name,
                hosts,
            )
            return conn
        except Exception as e:
            logger.warning(
                "[redis] Sentinel connection failed, falling back to REDIS_URL: %s",
                e,
            )

    conn = aioredis.from_url(redis_url, decode_responses=False)
    return conn


def create_redis_connection_decode():
    """Create a Redis connection with decode_responses=True (for WS/presence)."""
    import redis.asyncio as aioredis

    sentinel_hosts_env = os.environ.get("REDIS_SENTINEL_HOSTS", "")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    redis_password = os.environ.get("REDIS_PASSWORD")

    if sentinel_hosts_env:
        try:
            from redis.asyncio.sentinel import Sentinel

            hosts = _parse_sentinel_hosts(sentinel_hosts_env)
            master_name = os.environ.get("REDIS_SENTINEL_MASTER", "mymaster")
            sentinel_password = os.environ.get("REDIS_SENTINEL_PASSWORD")

            kwargs = {}
            if sentinel_password:
                kwargs["sentinel_kwargs"] = {"password": sentinel_password}
            if redis_password:
                kwargs["password"] = redis_password

            sentinel = Sentinel(hosts, **kwargs)
            conn = sentinel.master_for(master_name)
            logger.info(
                "[redis] Connected via Sentinel (decode) to master '%s' (%s)",
                master_name,
                hosts,
            )
            return conn
        except Exception as e:
            logger.warning(
                "[redis] Sentinel (decode) failed, falling back to REDIS_URL: %s",
                e,
            )

    return aioredis.from_url(redis_url, decode_responses=True)


def create_redis_sync():
    """Create a synchronous Redis connection (for non-async contexts)."""
    import redis

    sentinel_hosts_env = os.environ.get("REDIS_SENTINEL_HOSTS", "")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    redis_password = os.environ.get("REDIS_PASSWORD")

    if sentinel_hosts_env:
        try:
            from redis.sentinel import Sentinel

            hosts = _parse_sentinel_hosts(sentinel_hosts_env)
            master_name = os.environ.get("REDIS_SENTINEL_MASTER", "mymaster")
            sentinel_password = os.environ.get("REDIS_SENTINEL_PASSWORD")

            kwargs = {}
            if sentinel_password:
                kwargs["sentinel_kwargs"] = {"password": sentinel_password}
            if redis_password:
                kwargs["password"] = redis_password

            sentinel = Sentinel(hosts, **kwargs)
            conn = sentinel.master_for(master_name)
            logger.info("[redis-sync] Connected via Sentinel to master '%s'", master_name)
            return conn
        except Exception as e:
            logger.warning("[redis-sync] Sentinel failed, falling back: %s", e)

    return redis.from_url(redis_url, decode_responses=False)
