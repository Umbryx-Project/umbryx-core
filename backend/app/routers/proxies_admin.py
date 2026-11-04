"""Admin API for the egress proxy pool.

CRUD for endpoints and routing rules, a connectivity probe and a
resolution preview (which proxy a given category/target would use).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.crypto import decrypt_str, encrypt_str
from ..core.deps import require_infra_admin
from ..core.proxy_pool import (
    CATEGORIES,
    FAILURE_MODES,
    POLICIES,
    invalidate_cache,
    resolve,
)
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/admin/proxies", tags=["proxy-pool"])


def _endpoint_out(e: models.ProxyEndpoint) -> schemas.ProxyEndpointOut:
    return schemas.ProxyEndpointOut(
        id=e.id,
        name=e.name,
        scheme=e.scheme,
        host=e.host,
        port=e.port,
        username=e.username,
        has_password=bool(e.password_enc),
        tags=e.tags or [],
        enabled=e.enabled,
        last_check_at=e.last_check_at,
        last_ok=e.last_ok,
        latency_ms=e.latency_ms,
        created_at=e.created_at,
    )


def _route_out(r: models.ProxyRoute) -> schemas.ProxyRouteOut:
    return schemas.ProxyRouteOut(
        id=r.id,
        name=r.name,
        category=r.category,
        target_ref=r.target_ref,
        proxy_tags=r.proxy_tags or [],
        policy=r.policy,
        failure_mode=r.failure_mode,
        priority=r.priority,
        enabled=r.enabled,
        created_at=r.created_at,
    )


@router.get("", response_model=list[schemas.ProxyEndpointOut])
def list_endpoints(db: Annotated[Session, Depends(get_db)], _admin=Depends(require_infra_admin)):
    return [
        _endpoint_out(e)
        for e in db.query(models.ProxyEndpoint).order_by(models.ProxyEndpoint.created_at).all()
    ]


@router.post("", response_model=schemas.ProxyEndpointOut, status_code=201)
def create_endpoint(
    body: schemas.ProxyEndpointCreate,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
):
    if body.scheme not in ("http", "https", "socks5", "socks4"):
        raise HTTPException(400, f"unsupported scheme: {body.scheme}")
    from ..core.net import is_valid_host_literal, is_valid_port

    if not is_valid_host_literal(body.host):
        raise HTTPException(400, "invalid host: must be a hostname or IP literal")
    if not is_valid_port(body.port):
        raise HTTPException(400, "invalid port: must be 1-65535")
    e = models.ProxyEndpoint(
        id=new_id("pxy"),
        name=body.name.strip(),
        scheme=body.scheme,
        host=body.host.strip(),
        port=body.port,
        username=(body.username or "").strip() or None,
        password_enc=encrypt_str(body.password) if body.password else None,
        tags=body.tags or [],
        enabled=body.enabled,
        created_at=ts_now(),
    )
    db.add(e)
    db.commit()
    db.refresh(e)
    invalidate_cache()
    return _endpoint_out(e)


@router.delete("/{eid}", status_code=204)
def delete_endpoint(
    eid: str,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
):
    e = db.query(models.ProxyEndpoint).get(eid)
    if not e:
        raise HTTPException(404, "Proxy endpoint not found")
    db.delete(e)
    db.commit()
    invalidate_cache()


@router.patch("/{eid}", response_model=schemas.ProxyEndpointOut)
def patch_endpoint(
    eid: str,
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
):
    e = db.query(models.ProxyEndpoint).get(eid)
    if not e:
        raise HTTPException(404, "Proxy endpoint not found")
    connectivity_changed = False
    from ..core.net import is_valid_host_literal, is_valid_port

    if "host" in body and not is_valid_host_literal(str(body["host"])):
        raise HTTPException(400, "invalid host: must be a hostname or IP literal")
    if "port" in body and not is_valid_port(body["port"]):
        raise HTTPException(400, "invalid port: must be 1-65535")
    if "scheme" in body and body["scheme"] not in ("http", "https", "socks5", "socks4"):
        raise HTTPException(400, f"unsupported scheme: {body['scheme']}")
    for k in ("name", "scheme", "host", "port", "username", "tags", "enabled"):
        if k in body:
            setattr(e, k, body[k])
            if k in ("scheme", "host", "port"):
                connectivity_changed = True
    if connectivity_changed:
        # stale probe results refer to the old endpoint — reset health
        e.last_ok, e.latency_ms, e.last_check_at = None, None, None
    if "password" in body:
        e.password_enc = encrypt_str(body["password"]) if body["password"] else None
    db.commit()
    db.refresh(e)
    invalidate_cache()
    return _endpoint_out(e)


@router.post("/{eid}/check", response_model=schemas.ProxyCheckResult)
async def check_endpoint(
    eid: str,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
    body: dict | None = None,
):
    """Probe: TCP connect to the proxy itself + optional GET test_url through it."""
    import socket
    import time as _t

    e = db.query(models.ProxyEndpoint).get(eid)
    if not e:
        raise HTTPException(404, "Proxy endpoint not found")
    t0 = _t.monotonic()
    try:
        with socket.create_connection((e.host, e.port), timeout=5):
            pass
    except Exception as exc:
        e.last_ok, e.latency_ms, e.last_check_at = False, None, ts_now()
        db.commit()
        invalidate_cache()
        return schemas.ProxyCheckResult(ok=False, detail=f"tcp connect failed: {exc}")

    tcp_ms = int((_t.monotonic() - t0) * 1000)
    detail = f"tcp ok ({tcp_ms} ms)"
    ok = True
    test_url = (body or {}).get("test_url")
    if test_url:
        # SSRF-04 fix: grammar-validate the fetch target; never attach stored
        # proxy credentials to arbitrary hosts — only to the proxy itself,
        # which httpx handles via the proxy= mount (userinfo dropped).
        from urllib.parse import urlparse as _up

        from ..core.net import is_valid_host_literal

        _pu = _up(str(test_url))
        if (
            _pu.scheme not in ("http", "https")
            or not _pu.hostname
            or not is_valid_host_literal(_pu.hostname)
        ):
            raise HTTPException(400, "test_url must be a valid http(s) URL")
        pwd = decrypt_str(e.password_enc) if e.password_enc else ""
        auth = f"{e.username}:{pwd}@" if e.username else ""
        import httpx

        try:
            async with httpx.AsyncClient(
                proxy=f"{e.scheme}://{auth}{e.host}:{e.port}",
                trust_env=False,
                timeout=10,
            ) as client:
                r = await client.get(test_url)
                detail += f"; GET {test_url} → {r.status_code}"
                ok = r.status_code < 500
        except Exception as exc:
            ok = False
            detail += f"; GET failed: {exc}"

    e.last_ok, e.latency_ms, e.last_check_at = ok, tcp_ms, ts_now()
    db.commit()
    invalidate_cache()
    return schemas.ProxyCheckResult(ok=ok, latency_ms=tcp_ms, detail=detail)


@router.get("/routes", response_model=list[schemas.ProxyRouteOut])
def list_routes(db: Annotated[Session, Depends(get_db)], _admin=Depends(require_infra_admin)):
    return [
        _route_out(r)
        for r in db.query(models.ProxyRoute).order_by(models.ProxyRoute.priority).all()
    ]


@router.post("/routes", response_model=schemas.ProxyRouteOut, status_code=201)
def create_route(
    body: schemas.ProxyRouteCreate,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
):
    if body.category not in CATEGORIES:
        raise HTTPException(
            400, f"unknown category: {body.category} (one of {', '.join(CATEGORIES)})"
        )
    if body.policy not in POLICIES:
        raise HTTPException(400, f"unknown policy: {body.policy}")
    if body.failure_mode not in FAILURE_MODES:
        raise HTTPException(400, f"unknown failure_mode: {body.failure_mode}")
    r = models.ProxyRoute(
        id=new_id("pxr"),
        name=body.name.strip(),
        category=body.category,
        target_ref=(body.target_ref or "").strip() or None,
        proxy_tags=body.proxy_tags or [],
        policy=body.policy,
        failure_mode=body.failure_mode,
        priority=body.priority,
        enabled=body.enabled,
        created_at=ts_now(),
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    invalidate_cache()
    return _route_out(r)


@router.delete("/routes/{rid}", status_code=204)
def delete_route(
    rid: str,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
):
    r = db.query(models.ProxyRoute).get(rid)
    if not r:
        raise HTTPException(404, "Proxy route not found")
    db.delete(r)
    db.commit()
    invalidate_cache()


@router.patch("/routes/{rid}", response_model=schemas.ProxyRouteOut)
def patch_route(
    rid: str,
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
):
    r = db.query(models.ProxyRoute).get(rid)
    if not r:
        raise HTTPException(404, "Proxy route not found")
    for k in (
        "name",
        "category",
        "target_ref",
        "proxy_tags",
        "policy",
        "failure_mode",
        "priority",
        "enabled",
    ):
        if k in body:
            setattr(r, k, body[k])
    if "category" in body and body["category"] not in CATEGORIES:
        raise HTTPException(400, f"unknown category: {body['category']}")
    db.commit()
    db.refresh(r)
    invalidate_cache()
    return _route_out(r)


@router.get("/resolve", response_model=schemas.ResolvePreview)
def resolve_preview(
    category: str,
    db: Annotated[Session, Depends(get_db)],
    _admin=Depends(require_infra_admin),
    target_ref: str | None = None,
):
    info = resolve(db, category, target_ref)
    if info is None:
        return schemas.ResolvePreview(
            category=category, target_ref=target_ref, resolved=None, direct=True
        )
    return schemas.ResolvePreview(
        category=category,
        target_ref=target_ref,
        resolved=info.get("url"),
        route=info.get("route"),
        direct=False,
    )


@router.get("/categories")
def list_categories(_admin=Depends(require_infra_admin)):
    return {
        "categories": list(CATEGORIES),
        "policies": list(POLICIES),
        "failure_modes": list(FAILURE_MODES),
    }
