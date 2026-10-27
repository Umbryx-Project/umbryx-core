"""Proxy pool resolver: which proxy, if any, an egress call should use.

Design (proxy pool feature, 2026-09-17):
- ProxyRoute rules map (category, optional target_ref) to a filtered subset
  of ProxyEndpoints with a rotation policy. More specific routes win:
  exact category + exact target_ref > exact category > "all".
- round_robin: in-memory cursor per route. failover: stable first-alive.
- Endpoints are excluded after 3 consecutive reported failures for a
  10-minute cool-down window (in-memory circuit breaker; DB health fields
  are a separate, operator-driven snapshot from /check).
- No matching route / no usable endpoint: None (caller falls back to the
  global env proxy floor or direct), unless the route is fail_closed.

Config is read through a short-TTL cache; admin writes invalidate it.
"""

import threading
import time

from sqlalchemy.orm import Session

from ..models import ProxyEndpoint, ProxyRoute

CATEGORIES = (
    "all",
    "ai",
    "notifications",
    "provisioner",
    "c2",
    "dns",
    "webhooks",
    "pivots",
    "ssh",
    "updates",
)

POLICIES = ("round_robin", "failover")
FAILURE_MODES = ("fail_open", "fail_closed")

_CACHE_TTL = 5.0
_FAIL_THRESHOLD = 3
_COOLDOWN_S = 600.0

_lock = threading.Lock()
_cache: dict = {"ts": 0.0, "routes": [], "endpoints": []}
_rr_cursor: dict[str, int] = {}
_fail_state: dict[str, dict] = {}  # proxy_id -> {"fails": int, "until": ts}


def invalidate_cache() -> None:
    with _lock:
        _cache["ts"] = 0.0


def _load(db: Session) -> tuple[list, list]:
    now = time.monotonic()
    with _lock:
        fresh = now - _cache["ts"] < _CACHE_TTL
        if fresh:
            return _cache["routes"], _cache["endpoints"]
    routes = [r for r in db.query(ProxyRoute).filter(ProxyRoute.enabled).all()]
    endpoints = [e for e in db.query(ProxyEndpoint).filter(ProxyEndpoint.enabled).all()]
    with _lock:
        _cache.update(ts=now, routes=routes, endpoints=endpoints)
    return routes, endpoints


def report_failure(proxy_id: str) -> None:
    with _lock:
        st = _fail_state.setdefault(proxy_id, {"fails": 0, "until": 0.0})
        st["fails"] += 1
        if st["fails"] >= _FAIL_THRESHOLD:
            st["until"] = time.monotonic() + _COOLDOWN_S


def report_success(proxy_id: str) -> None:
    with _lock:
        _fail_state.pop(proxy_id, None)


def _alive(endpoint) -> bool:
    if endpoint.last_ok is False:
        return False  # operator's /check marked it dead
    with _lock:
        st = _fail_state.get(endpoint.id)
        if st and time.monotonic() < st["until"]:
            return False
    return True


def _url(endpoint) -> str:
    auth = ""
    if endpoint.username:
        # password_enc is decrypted by the caller-side helper (net.py);
        # here we take a ready-made auth string to avoid crypto in the hot path
        auth = f"{endpoint.username}:{endpoint.password_clear or ''}@"
    return f"{endpoint.scheme}://{auth}{endpoint.host}:{endpoint.port}"


def _pick(route, candidates: list):
    if not candidates:
        return None
    if route.policy == "failover":
        return candidates[0]
    # round_robin
    with _lock:
        i = _rr_cursor.get(route.id, 0)
        _rr_cursor[route.id] = (i + 1) % max(1, len(candidates))
    return candidates[i % len(candidates)]


def _route_score(route, category: str, target_ref: str | None) -> int | None:
    cat_match = route.category == category
    all_match = route.category == "all"
    if not cat_match and not all_match:
        return None
    if route.target_ref is not None and route.target_ref != (target_ref or ""):
        return None
    return (2 if cat_match else 0) + (2 if route.target_ref is not None else 0)


def resolve(db: Session, category: str, target_ref: str | None = None) -> dict | None:
    """Return {'proxy_id', 'url', 'failure_mode'} or None (direct / floor)."""
    if category not in CATEGORIES:
        category = "all"
    routes, endpoints = _load(db)

    best, best_score = None, -1
    for r in routes:
        s = _route_score(r, category, target_ref)
        if s is None:
            continue
        if s > best_score or (s == best_score and best and r.priority < best.priority):
            best, best_score = r, s
    if not best:
        return None

    tags = set(best.proxy_tags or [])
    candidates = [
        e
        for e in endpoints
        if (not tags or tags & set(e.tags or [])) and _alive(e)
    ]
    # stable order for failover: priority-less, creation order
    candidates.sort(key=lambda e: e.created_at or "")
    chosen = _pick(best, candidates)
    if chosen is None:
        if best.failure_mode == "fail_closed":
            return {"error": "no usable proxy (fail_closed route)"}
        return None
    from ..core.crypto import decrypt_str

    pwd = decrypt_str(chosen.password_enc) if chosen.password_enc else ""
    auth = f"{chosen.username}:{pwd}@" if chosen.username else ""
    return {
        "proxy_id": chosen.id,
        "url": f"{chosen.scheme}://{auth}{chosen.host}:{chosen.port}",
        "failure_mode": best.failure_mode,
        "route": best.name,
    }
