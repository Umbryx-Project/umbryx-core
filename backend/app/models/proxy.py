"""Egress proxy pool: endpoints + routing rules.

The platform's own outbound traffic (AI providers, notifications, C2
integrations, DNS plugins, provisioners, pivots, SSH executor) can be
routed through a pool of proxies with per-category / per-target rules
(proxy pool feature, 2026-09-17). The legacy single global
`outbound_proxy` setting remains the floor: categories without a matching
route keep using the env-based global proxy (or direct).
"""

from sqlalchemy import Boolean, Column, Integer, String

from ..database import Base
from ._types import pg_array as ARRAY


class ProxyEndpoint(Base):
    __tablename__ = "proxy_endpoints"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    scheme = Column(String, nullable=False, default="http")  # http|https|socks5|socks4
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    username = Column(String, nullable=True)
    password_enc = Column(String, nullable=True)  # encrypted (encrypt_str)
    tags = Column(ARRAY(String), nullable=True, default=list)
    enabled = Column(Boolean, nullable=False, default=True)
    # health snapshot, updated by POST /api/admin/proxies/{id}/check
    # and consulted by the resolver (unknown/null = assumed alive)
    last_check_at = Column(String, nullable=True)
    last_ok = Column(Boolean, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(String, nullable=False)


class ProxyRoute(Base):
    __tablename__ = "proxy_routes"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    # one of CATEGORIES in core/proxy_pool.py, or "all"
    category = Column(String, nullable=False)
    # optional exact target selector, e.g. "ai_provider:prov123" —
    # routes with target_ref win over category-wide ones
    target_ref = Column(String, nullable=True)
    # only use endpoints carrying at least one of these tags (empty = all)
    proxy_tags = Column(ARRAY(String), nullable=True, default=list)
    # round_robin | failover
    policy = Column(String, nullable=False, default="round_robin")
    # fail_open: fall back to direct/global when no proxy is usable
    # fail_closed: raise (caller surfaces the error)
    failure_mode = Column(String, nullable=False, default="fail_open")
    # smaller value = higher precedence among equally specific routes
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(String, nullable=False)
