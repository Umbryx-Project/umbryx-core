"""C2 operations API — on-demand listeners and payload generation.

The deploy-time push (c2_push) covers the blueprint flow; these endpoints
make listeners and payload builds first-class operations on any Adaptix
integration, with live port exposure (k8s Service patch — no pod restart,
C2 data survives) and TLS routed to the redirector when one exists.
"""

from __future__ import annotations

import base64
import hashlib
from io import BytesIO
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.c2ops.ops import (
    get_integration,
    listener_context,
    ops_create_listener,
    ops_generate_payload,
    ops_list_listeners,
    ops_stop_listener,
)
from ..core.crypto import encrypt_bytes
from ..core.deps import get_current_user
from ..core.enums import UserRole
from ..core.events import log_event
from ..core.storage import get_storage_backend
from ..core.utils import new_id, safe_upload_name, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/infra-v2/c2", tags=["c2-ops"])


class ListenerBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=63)
    listener_type: str = "http"
    port: int = Field(8443, ge=1, le=65535)
    callback: str = ""
    domain: str = ""
    ssl: bool | None = None


class PayloadBody(BaseModel):
    listener: str
    agent: str = "beacon"
    pid: str | None = None  # loot target; defaults to the integration's first project
    config: dict = {}


def _get_int_or_404(db: Session, iid: str) -> dict:
    cfg = get_integration(db, iid)
    supported = ("adaptix", "mythic", "sliver")
    if not cfg or cfg.get("type") not in supported or not cfg.get("enabled", True):
        raise HTTPException(404, f"No enabled C2 integration of a supported type {supported}: '{iid}'")
    return cfg


def _require_admin(user: models.User) -> None:
    if user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403, "Platform admins only")


@router.get("/{iid}/listeners")
async def api_list_listeners(
    iid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_admin(user)
    cfg = _get_int_or_404(db, iid)
    try:
        listeners = await ops_list_listeners(db, cfg)
        return {"listeners": listeners, "context": listener_context(db, cfg, listeners)}
    except Exception as exc:
        raise HTTPException(502, f"C2 unreachable: {exc}") from exc


@router.post("/{iid}/listeners")
async def api_create_listener(
    iid: str,
    body: ListenerBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_admin(user)
    cfg = _get_int_or_404(db, iid)
    result = await ops_create_listener(db, cfg, body.model_dump())
    if result.get("ok"):
        # Standalone (project-less) integrations: timeline_events.pid is NOT NULL
        # with an FK to projects, so skip event logging when there is no project.
        pid = (cfg.get("project_ids") or [None])[0] or ""
        if pid:
            log_event(
                db,
                pid,
                user.username,
                "c2",
                "listener",
                f"C2 listener '{body.name}' created ({result['listener']['type']} :{body.port})",
                {"integration": iid, "exposure": result.get("exposure", {})},
            )
            db.commit()
        return result
    raise HTTPException(502, result.get("message", "listener creation failed"))


@router.delete("/{iid}/listeners/{name}")
async def api_stop_listener(
    iid: str,
    name: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_admin(user)
    cfg = _get_int_or_404(db, iid)
    result = await ops_stop_listener(db, cfg, name)
    if result.get("ok"):
        return result
    raise HTTPException(502, result.get("message", "listener stop failed"))


@router.post("/{iid}/payloads")
async def api_generate_payload(
    iid: str,
    body: PayloadBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_admin(user)
    cfg = _get_int_or_404(db, iid)
    result = await ops_generate_payload(cfg, body.model_dump())
    if not result.get("ok"):
        raise HTTPException(502, result.get("message", "generation failed"))

    pid = body.pid or (cfg.get("project_ids") or [None])[0]
    if not pid:
        # Standalone (project-less) integration: no loot storage available —
        # return the payload inline so operators can still download it.
        raw = result["payload"]
        b64 = raw if isinstance(raw, str) else base64.b64encode(raw).decode()
        blob = base64.b64decode(b64)
        return {
            "ok": True,
            "filename": result["filename"],
            "sha256": hashlib.sha256(blob).hexdigest(),
            "size": len(blob),
            "payload": b64,
            "note": "standalone integration: payload returned inline (no project loot)",
        }

    payload: bytes = result["payload"]
    filename = result["filename"]

    loot = models.Loot(
        id=new_id("loot"),
        pid=pid,
        loot_type="payload",
        value=f"{filename} (listener {body.listener})",
        description=f"Generated from C2 listener '{body.listener}' via integration '{cfg.get('name', iid)}'",
        filename=filename,
        content_type="application/octet-stream",
        file_size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        artifact_type="file",
        ts=ts_now(),
    )
    db.add(loot)
    db.flush()

    storage = get_storage_backend()
    safe_name = safe_upload_name(filename)
    loot.storage_path = await storage.save(
        loot.pid, f"loot/{loot.id}{Path(safe_name).suffix or '.bin'}",
        BytesIO(encrypt_bytes(payload)),
    )
    loot.filename = safe_name
    loot.public_url = f"/api/uploads/{loot.pid}/loot/{loot.id}"
    loot.file_encrypted = True
    db.commit()

    # Auto-publish to the engagement's dropper (pwndrop) — the operator
    # gets a ready-to-send public link right away (2026-09-22 case).
    dropper_url = None
    try:
        # The dropper is a service inside a deployed stack, so publishing to
        # it belongs to the Enterprise package. Payload generation itself is
        # a Community capability and must not fail because there is nowhere
        # to host the result — the operator still gets the payload, just no
        # ready-made link.
        from ..core.editions import ee_import

        dropper = ee_import("infra.dropper")
        pub = (
            dropper.publish_payload(db, safe_name, payload, pid=pid, stack_id=cfg.get("stack_id"))
            if dropper is not None
            else None
        )
        if pub:
            dropper_url = pub["url"]
            loot.dropper_url = dropper_url
            db.commit()
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger(__name__).warning("dropper autopublish failed: %s", exc)

    log_event(
        db,
        pid,
        user.username,
        "loot",
        "create",
        f"C2 payload generated: {safe_name} ({len(payload)} bytes, listener '{body.listener}')"
        + (f" → dropper: {dropper_url}" if dropper_url else ""),
        {
            "integration": iid,
            "listener": body.listener,
            "sha256": loot.sha256,
            **({"dropper_url": dropper_url} if dropper_url else {}),
        },
    )
    db.commit()

    return {
        "ok": True,
        "loot_id": loot.id,
        "filename": safe_name,
        "sha256": loot.sha256,
        "size": len(payload),
        **({"dropper_url": dropper_url} if dropper_url else {}),
    }
