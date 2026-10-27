"""Live status of the optional multi-node HA layer (docker-compose.ha.yml).

Both halves are entirely optional and independently detected:
  - Postgres: reads pg_auto_failover's own bookkeeping table
    (pgautofailover.node) via a direct connection to the monitor —
    HA_MONITOR_HOST unset means "not deployed in HA mode", not an error.
  - Redis: reuses the app's own REDIS_SENTINEL_HOSTS/MASTER/PASSWORD
    (the same ones redis_factory.py uses to actually connect) and asks
    Sentinel directly for master/replica/sentinel state.

Never touches write paths — this is read-only monitoring, safe to expose
to any platform_admin regardless of who is currently primary.
"""

from __future__ import annotations

import os


def _monitor_dsn() -> str | None:
    host = os.environ.get("HA_MONITOR_HOST", "")
    if not host:
        return None
    port = os.environ.get("HA_MONITOR_PORT", "5433")
    db = os.environ.get("HA_MONITOR_DB", "pg_auto_failover")
    user = os.environ.get("HA_MONITOR_USER", "umbryx_monitor")
    password = os.environ.get("HA_MONITOR_PASSWORD", "")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}" "?sslmode=require&connect_timeout=3"


def get_postgres_ha_status() -> dict | None:
    """Return pg_auto_failover node states, or None if HA_MONITOR_HOST isn't set."""
    dsn = _monitor_dsn()
    if not dsn:
        return None

    import psycopg2
    import psycopg2.extras

    try:
        conn = psycopg2.connect(dsn)
    except Exception as exc:
        return {"reachable": False, "error": str(exc)[:300], "nodes": []}

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT nodeid, nodename, nodehost, nodeport, goalstate,
                       reportedstate, reportedtli, reportedlsn, formationid, groupid
                FROM pgautofailover.node
                ORDER BY nodeid
                """)
            rows = [dict(r) for r in cur.fetchall()]
        return {"reachable": True, "error": None, "nodes": rows}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)[:300], "nodes": []}
    finally:
        conn.close()


def get_redis_ha_status() -> dict | None:
    """Return Redis Sentinel status, or None if REDIS_SENTINEL_HOSTS isn't set."""
    sentinel_hosts_env = os.environ.get("REDIS_SENTINEL_HOSTS", "")
    if not sentinel_hosts_env:
        return None

    from .redis_factory import _parse_sentinel_hosts

    hosts = _parse_sentinel_hosts(sentinel_hosts_env)
    master_name = os.environ.get("REDIS_SENTINEL_MASTER", "mymaster")
    sentinel_password = os.environ.get("REDIS_SENTINEL_PASSWORD") or None

    import redis
    from redis.sentinel import Sentinel

    sentinel_kwargs = {"socket_timeout": 3}
    if sentinel_password:
        sentinel_kwargs["password"] = sentinel_password
    sentinel = Sentinel(hosts, sentinel_kwargs=sentinel_kwargs)

    result = {"reachable": False, "error": None, "master": None, "sentinels": [], "replicas": []}
    try:
        master_info = sentinel.discover_master(master_name)
        result["master"] = {"host": master_info[0], "port": master_info[1]}
        result["reachable"] = True
    except Exception as exc:
        result["error"] = str(exc)[:300]

    for host, port in hosts:
        entry = {"host": host, "port": port, "reachable": False, "flags": None, "quorum": None}
        try:
            r = redis.Redis(host=host, port=port, decode_responses=True, **sentinel_kwargs)
            master = r.execute_command("SENTINEL", "MASTER", master_name)
            info = dict(zip(master[0::2], master[1::2])) if master else {}
            entry["reachable"] = True
            entry["flags"] = info.get("flags")
            entry["quorum"] = info.get("quorum")
            entry["num_slaves"] = info.get("num-slaves")
            entry["num_other_sentinels"] = info.get("num-other-sentinels")
        except Exception as exc:
            entry["error"] = str(exc)[:200]
        result["sentinels"].append(entry)

    try:
        replicas = sentinel.discover_slaves(master_name)
        result["replicas"] = [{"host": h, "port": p} for h, p in replicas]
    except Exception:
        pass

    return result


def get_ha_status() -> dict:
    pg = get_postgres_ha_status()
    redis_status = get_redis_ha_status()
    return {
        "enabled": pg is not None or redis_status is not None,
        "postgres": pg,
        "redis": redis_status,
    }
