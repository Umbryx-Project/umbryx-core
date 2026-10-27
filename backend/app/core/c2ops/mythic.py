"""Mythic operations backend — payload generation over GraphQL.

Mythic has no listener objects: C2 profiles run inside the Mythic server
per operation and are configured on payloads. So this backend maps:

- list_listeners → available C2 profiles (the "listener types" of Mythic)
- create_listener → 501 with an explanation (Mythic's model), never a fake
- generate_payload → createPayload mutation (+ build) and the artifact
  download via the documented files endpoint

Auth mirrors routers/c2/_mythic.py: `apitoken` header when configured,
username/password -> JWT Bearer otherwise; GraphQL posts to /graphql/.
"""

from __future__ import annotations

import logging

import httpx

from ...core.crypto import decrypt_str

logger = logging.getLogger(__name__)

# Security audit 2026-10-07 (M2): every client below honors the
# integration's verify_ssl (default ON) — the agent-login POST carries the
# C2 admin password and hardcoded verify=False exposed it to MITM.

_MYTHIC_VERIFY_DEFAULT = True


def _auth_headers(cfg: dict) -> dict:
    token = (cfg.get("token") or "").strip()
    if token:
        return {"apitoken": token}
    return {"Authorization": f"Bearer {_login(cfg)}"}


def _login(cfg: dict) -> str:
    password = cfg.get("password", "")
    if password.startswith("__enc__"):
        password = decrypt_str(password)
    url = cfg.get("url", "").rstrip("/")
    with httpx.Client(verify=cfg.get("verify_ssl", _MYTHIC_VERIFY_DEFAULT), timeout=30) as client:
        r = client.post(
            f"{url}/auth",
            json={
                "username": cfg.get("username") or "mythic_admin",
                "password": password,
                "scripting_version": "0.1",
            },
        )
        r.raise_for_status()
        jwt = r.json().get("access_token") or r.json().get("token") or ""
    if not jwt:
        raise RuntimeError("Mythic login: no access_token in response")
    return jwt


def _gql(cfg: dict, client: httpx.Client, headers: dict, query: str, variables: dict | None = None) -> dict:
    url = cfg.get("url", "").rstrip("/")
    r = client.post(f"{url}/graphql/", json={"query": query, **({"variables": variables} if variables else {})}, headers=headers)
    r.raise_for_status()
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"Mythic GraphQL error: {data['errors']}")
    return data.get("data", {})


def list_listeners(cfg: dict) -> list[dict]:
    """Available C2 profiles — Mythic's closest analogue of listener types."""
    headers = _auth_headers(cfg)
    with httpx.Client(verify=cfg.get("verify_ssl", _MYTHIC_VERIFY_DEFAULT), timeout=30) as client:
        data = _gql(
            cfg, client, headers,
            "query { c2profile { id name description } }",
        )
    out = []
    for p in data.get("c2profile", []) or []:
        out.append(
            {
                "l_name": p.get("name", ""),
                "l_reg_name": "mythic-c2-profile",
                "l_status": "available",
                "l_bind_host": "",
                "l_bind_port": "",
                "l_agent_addr": "",
            }
        )
    return out


def create_listener(cfg: dict, body: dict) -> dict:
    from fastapi import HTTPException

    raise HTTPException(
        501,
        "Mythic has no standalone listeners: C2 profiles are configured per "
        "payload (generate a payload with the profile instead) or enabled in "
        "the operation's profile settings.",
    )


def stop_listener(cfg: dict, name: str, listener_type: str = "") -> dict:
    from fastapi import HTTPException

    raise HTTPException(501, "Mythic listeners are not stoppable objects — see create_listener note.")


def list_payload_types(cfg: dict) -> list[str]:
    headers = _auth_headers(cfg)
    with httpx.Client(verify=cfg.get("verify_ssl", _MYTHIC_VERIFY_DEFAULT), timeout=30) as client:
        data = _gql(cfg, client, headers, "query { payloadtype { name } }")
    return [p.get("name", "") for p in data.get("payloadtypes", []) or []]


def generate_payload(cfg: dict, body: dict) -> dict:
    """createPayload + buildPayload; artifact fetched via the files endpoint.

    body: {listener: <c2 profile name>, agent: <payload type>, config: {...}}
    Mythic-specific config passthrough keys (all optional):
      operation, build_parameters, filename, description
    """
    agent = body.get("agent") or ""
    if not agent:
        types = list_payload_types(cfg)
        if not types:
            raise RuntimeError("Mythic: no payload types available")
        agent = types[0]

    profile = body.get("listener") or "http"
    headers = _auth_headers(cfg)
    mythic_cfg = body.get("config", {}) or {}

    # Live Mythic schema: createPayload takes a JSON string (payloadDefinition)
    # and returns {uuid,status,error}; the build is tracked by polling.
    mutation = """
    mutation CreatePayload($pd: String!) {
      createPayload(payloadDefinition: $pd) { uuid status error }
    }
    """
    # Mythic's OPSEC check rejects builds with the default callback host; if
    # the caller did not supply C2 parameters, derive sane defaults from the
    # integration URL (edge nodeport = TLS-terminating redirector for the http profile).
    # c2_profile_parameters is a map {name: value}; accept either a map or a
    # list of {name, value} entries from the API caller.
    c2_params = mythic_cfg.get("c2_params") or {}
    if isinstance(c2_params, list):
        c2_params = {p.get("name", ""): p.get("value") for p in c2_params if p.get("name")}
    if not c2_params and profile in ("http", "https"):
        base = (cfg.get("url") or "").rstrip("/")
        host_part = base.split(":")[0] + ":" + base.split(":")[1] if ":" in base else base
        port_part = base.rsplit(":", 1)[-1] if base.count(":") == 2 else "443"
        c2_params = {"callback_host": host_part, "callback_port": port_part}
    payload_input = {
        "payload_type": agent,
        "c2_profiles": [{"c2_profile": profile, "c2_profile_parameters": c2_params}],
        "selected_os": mythic_cfg.get("os", "Windows"),
        "filename": mythic_cfg.get("filename", ""),
        "description": mythic_cfg.get("description", f"umbryx c2-ops build ({profile})"),
    }
    if mythic_cfg.get("operation"):
        payload_input["operation_name"] = mythic_cfg["operation"]
    # payload containers expect a map (never null) — Apollo's builder
    # iterates over build_parameters unconditionally.
    payload_input["build_parameters"] = mythic_cfg.get("build_parameters") or {}

    import json as _json
    import time as _time

    with httpx.Client(verify=cfg.get("verify_ssl", _MYTHIC_VERIFY_DEFAULT), timeout=60) as client:
        try:
            data = _gql(cfg, client, headers, mutation, {"pd": _json.dumps(payload_input)})
            puuid = (data.get("createPayload") or {}).get("uuid")
        except RuntimeError:
            # Hasura retries the action when the build outlives its timeout, and
            # the server may answer both calls in one body ("not a valid json").
            # The payload is still created — fall back to the newest payload.
            puuid = None
        if not puuid:
            q = (
                "query { payload(order_by: {id: desc}, limit: 1) "
                "{ uuid build_phase description } }"
            )
            data = _gql(cfg, client, headers, q)
            rows = data.get("payload") or []
            if rows and rows[0].get("uuid"):
                puuid = rows[0]["uuid"]
            else:
                raise RuntimeError("Mythic createPayload failed and no payload row exists")

        poll = """
        query($u: String!) {
          payload(where: {uuid: {_eq: $u}}) {
            build_phase build_message filemetum { agent_file_id filename }
          }
        }
        """
        deadline = _time.time() + 300
        built = {}
        while _time.time() < deadline:
            _time.sleep(5)
            data = _gql(cfg, client, headers, poll, {"u": puuid})
            rows = data.get("payload") or []
            built = rows[0] if rows else {}
            phase = (built.get("build_phase") or "").lower()
            if phase in ("success", "error"):
                break
        if (built.get("build_phase") or "").lower() != "success":
            raise RuntimeError(
                f"Mythic build failed: {built.get('build_message') or built.get('build_phase')}"
            )
        file_meta = built.get("filemetum") or {}
        file_id = file_meta.get("agent_file_id")
        if not file_id:
            raise RuntimeError(f"Mythic build produced no file: {built}")

        url = cfg.get("url", "").rstrip("/")
        r = client.get(f"{url}/direct/download/{file_id}", headers=headers)
        r.raise_for_status()

    filename = mythic_cfg.get("filename") or f"{agent}_{profile}.bin"
    return {"ok": True, "filename": filename, "payload": r.content, "config": mythic_cfg}
