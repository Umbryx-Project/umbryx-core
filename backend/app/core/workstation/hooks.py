"""
Post-provisioning hooks for operator workstations.

Called by workstation/provider.py after a workstation container is ready.
Creates a Host record in the project so the workstation shows up in the host list.
"""

import logging

from sqlalchemy.orm import Session

from ... import models
from ...core.utils import new_id, ts_now

logger = logging.getLogger(__name__)


async def on_workstation_ready(ws: models.OperatorWorkstation, db: Session) -> None:
    """Called when a workstation container becomes ready. Upserts a project Host."""
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    image = meta.get("image", "")
    ports = meta.get("ports", [])
    container_name = meta.get("container_name", "")

    host_ip = "localhost"

    host_data = {
        "ip": host_ip,
        "hostname": container_name or ws.name,
        "os": _os_from_image(image),
        "status": "accessible",
        "source": "workstation",
        "workstation_id": ws.id,
        "ports": ports,
        "image": image,
    }

    _upsert_project_host(ws.project_id, host_data, db)

    event = models.InfraEvent(
        id=new_id("ie"),
        project_id=ws.project_id,
        workstation_id=ws.id,
        event_type="workstation.ready",
        payload={"host": host_data},
        timestamp=ts_now(),
    )
    db.add(event)
    db.commit()


def _upsert_project_host(project_id: str, host_data: dict, db: Session) -> None:
    ip = host_data.get("ip", "")
    if not ip:
        return

    source = host_data.get("source", "")
    ports = [str(p) for p in (host_data.get("ports") or [])]

    existing = (
        db.query(models.Host)
        .filter(
            models.Host.pid == project_id,
            models.Host.ip == ip,
        )
        .first()
    )

    if existing:
        if host_data.get("hostname") and not existing.hostname:
            existing.hostname = host_data["hostname"]
        if host_data.get("os") and not existing.os:
            existing.os = host_data["os"]
        existing.status = host_data.get("status", "alive")
        if source and not existing.import_source:
            existing.import_source = source
        if ports:
            existing.ports = list(dict.fromkeys([*(existing.ports or []), *ports]))
        if source and source not in (existing.tags or []):
            existing.tags = [*(existing.tags or []), source]
    else:
        host = models.Host(
            id=new_id("h"),
            pid=project_id,
            ip=ip,
            hostname=host_data.get("hostname", ""),
            os=host_data.get("os", ""),
            status=host_data.get("status", "alive"),
            ports=ports,
            tags=[source] if source else [],
            import_source=source,
        )
        db.add(host)
    db.commit()


def _os_from_image(image: str) -> str:
    image_lower = (image or "").lower()
    if "kali" in image_lower:
        return "Linux (Kali)"
    if "ubuntu" in image_lower:
        return "Linux (Ubuntu)"
    if "parrot" in image_lower:
        return "Linux (Parrot)"
    if "blackarch" in image_lower:
        return "Linux (BlackArch)"
    if "windows" in image_lower or "servercore" in image_lower:
        return "Windows"
    return "Linux"
