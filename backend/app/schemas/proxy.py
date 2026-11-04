"""Proxy pool schemas (admin CRUD + resolution preview)."""

from pydantic import BaseModel, Field


class ProxyEndpointCreate(BaseModel):
    name: str = Field(..., min_length=1)
    scheme: str = "http"  # http|https|socks5|socks4
    host: str = Field(..., min_length=1)
    port: int = Field(..., ge=1, le=65535)
    username: str | None = None
    password: str | None = None
    tags: list[str] = []
    enabled: bool = True


class ProxyEndpointOut(BaseModel):
    id: str
    name: str
    scheme: str
    host: str
    port: int
    username: str | None = None
    has_password: bool = False
    tags: list[str] = []
    enabled: bool = True
    last_check_at: str | None = None
    last_ok: bool | None = None
    latency_ms: int | None = None
    created_at: str


class ProxyRouteCreate(BaseModel):
    name: str = Field(..., min_length=1)
    category: str
    target_ref: str | None = None
    proxy_tags: list[str] = []
    policy: str = "round_robin"
    failure_mode: str = "fail_open"
    priority: int = 100
    enabled: bool = True


class ProxyRouteOut(BaseModel):
    id: str
    name: str
    category: str
    target_ref: str | None = None
    proxy_tags: list[str] = []
    policy: str
    failure_mode: str
    priority: int
    enabled: bool
    created_at: str


class ProxyCheckResult(BaseModel):
    ok: bool
    latency_ms: int | None = None
    detail: str = ""


class ResolvePreview(BaseModel):
    category: str
    target_ref: str | None = None
    resolved: str | None = None
    route: str | None = None
    direct: bool = True
