from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..core.deps import require_admin
from ..core.logging_setup import get_logger
from ..core.upload_guard import read_upload_capped
from ..database import get_db
from ..plugins.bundle_loader import (
    PluginError,
    get_plugin_frontend_js,
    install_plugin,
    list_installed_plugins,
    toggle_plugin,
    uninstall_plugin,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/plugins", tags=["plugins"])


@router.get("")
async def plugins_list(db: Session = Depends(get_db)):
    return list_installed_plugins(db)


@router.post("/install")
async def plugin_install(
    file: UploadFile = File(...),
    x_plugin_signature: str | None = Header(None, alias="X-Plugin-Signature"),
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    from ..core.plan import PlanFeature, instance_has_feature

    if not instance_has_feature(PlanFeature.PLUGIN_UPLOAD, db):
        raise HTTPException(402, "Installing plugins requires the Pro plan or higher.")

    if not file.filename or not file.filename.endswith(".rnplugin"):
        raise HTTPException(400, "Bundle must be a .rnplugin file")

    content = await read_upload_capped(file, 100 * 1024 * 1024, None)
    import asyncio

    def _write_tmp() -> str:
        with tempfile.NamedTemporaryFile(suffix=".rnplugin", delete=False) as tmp:
            tmp.write(content)
            return tmp.name

    tmp_path = Path(await asyncio.to_thread(_write_tmp))

    try:
        plugin = install_plugin(tmp_path, db, signature=x_plugin_signature)
        return {
            "id": plugin.id,
            "version": plugin.version,
            "title": plugin.manifest.get("plugin", {}).get("title", plugin.id),
            "installed_at": plugin.installed_at,
        }
    except PluginError as e:
        raise HTTPException(400, str(e))
    finally:
        tmp_path.unlink(missing_ok=True)


@router.delete("/{plugin_id}")
async def plugin_uninstall(
    plugin_id: str,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    try:
        ok = uninstall_plugin(plugin_id, db)
    except PluginError as e:
        raise HTTPException(400, str(e))
    if not ok:
        raise HTTPException(404, "Plugin not found")
    return {"ok": True}


@router.patch("/{plugin_id}")
async def plugin_toggle(
    plugin_id: str,
    body: dict = None,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    if body is None:
        body = {}
    enabled = body.get("enabled")
    if enabled is None:
        raise HTTPException(400, "enabled field required")
    plugin = toggle_plugin(plugin_id, bool(enabled), db)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    return {"id": plugin.id, "enabled": plugin.enabled}


@router.get("/{plugin_id}/frontend.js")
async def plugin_frontend_js(
    plugin_id: str,
    db: Session = Depends(get_db),
):
    # Security audit 2026-10-09 (LOW): the id feeds a filesystem path —
    # reject anything outside the manifest charset ([a-z0-9_-]).
    import re as _re

    if not _re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", plugin_id or ""):
        raise HTTPException(400, "Invalid plugin id")
    js = get_plugin_frontend_js(plugin_id)
    if js is None:
        raise HTTPException(404, "Plugin has no frontend module")
    from fastapi.responses import Response

    return Response(content=js, media_type="application/javascript")
