"""Egress client factory: single place where outbound HTTP clients are made.

Every platform-internal outbound call should use one of these instead of
`httpx.AsyncClient(...)` directly, so proxy-pool routing
(core/proxy_pool.py) applies:

    async with egress_async_client("ai", f"ai_provider:{pid}", timeout=300) as client:
        ...

Semantics:
- A matching proxy-pool route wins: the client is built with an explicit
  proxy and trust_env disabled (the global env floor must not stack on
  top of an explicit route proxy).
- No route → trust_env stays on: the legacy global `outbound_proxy`
  (HTTP_PROXY/HTTPS_PROXY env) applies as the floor, else direct.
- Proxy errors on route-selected clients should be reported back via
  report_egress_failure / report_egress_success so the circuit breaker
  can rotate the pool.
"""

import httpx

from . import proxy_pool


def _build(proxy_info: dict | None, kwargs: dict) -> httpx.AsyncClient:
    if proxy_info and proxy_info.get("url"):
        kwargs = dict(kwargs)
        kwargs["proxy"] = proxy_info["url"]
        kwargs["trust_env"] = False
    return httpx.AsyncClient(**kwargs)


def egress_async_client(category: str, target_ref: str | None = None, db=None, **kwargs):
    """httpx.AsyncClient routed per proxy-pool rules for *category*."""
    proxy_info = None
    if db is not None:
        proxy_info = proxy_pool.resolve(db, category, target_ref)
    if proxy_info and proxy_info.get("error"):
        raise RuntimeError(proxy_info["error"])
    client = _build(proxy_info, kwargs)
    client._umbryx_proxy_id = (proxy_info or {}).get("proxy_id")  # type: ignore[attr-defined]
    return client


def egress_sync_client(category: str, target_ref: str | None = None, db=None, **kwargs):
    """httpx.Client (sync) routed per proxy-pool rules for *category*."""
    proxy_info = None
    if db is not None:
        proxy_info = proxy_pool.resolve(db, category, target_ref)
    if proxy_info and proxy_info.get("error"):
        raise RuntimeError(proxy_info["error"])
    if proxy_info and proxy_info.get("url"):
        kwargs = dict(kwargs)
        kwargs["proxy"] = proxy_info["url"]
        kwargs["trust_env"] = False
    client = httpx.Client(**kwargs)
    client._umbryx_proxy_id = (proxy_info or {}).get("proxy_id")  # type: ignore[attr-defined]
    return client


def client_proxy_id(client) -> str | None:
    """Proxy-pool id a client was routed through (for failure reporting)."""
    return getattr(client, "_umbryx_proxy_id", None)


def report_egress_failure(client) -> None:
    pid = client_proxy_id(client)
    if pid:
        proxy_pool.report_failure(pid)


def report_egress_success(client) -> None:
    pid = client_proxy_id(client)
    if pid:
        proxy_pool.report_success(pid)
