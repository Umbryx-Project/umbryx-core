"""
Firewall/router config upload → parse → project enrichment.

POST /api/projects/{pid}/firewall-configs/detect  — vendor auto-detection only
POST /api/projects/{pid}/firewall-configs/preview  — parse + dry-run enrichment counts/diff, no writes
POST /api/projects/{pid}/firewall-configs/apply    — persist + queue async parse+enrich job
GET  /api/projects/{pid}/firewall-configs          — upload history
GET  /api/projects/{pid}/firewall-configs/{id}/diff — diff vs. previous upload for the same device
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import log_event
from ..core.firewall_config_diff import diff_parsed_configs
from ..core.firewall_enrich import enrich_project_from_config, parsed_config_to_safe_dict
from ..core.firewall_parsers import FirewallParserRegistry
from ..core.job_runner import schedule_job_run
from ..core.job_tracker import queue_job
from ..core.secure_files import save_encrypted
from ..core.upload_guard import read_upload_capped
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(tags=["firewall_configs"])

_PERM = "findings.create"  # same permission import_scanners.py uses for all import endpoints
_MAX_CONFIG_SIZE = 5 * 1024 * 1024  # 5 MB — spec §5 upload size cap


async def _read_upload(file: UploadFile | None, raw_text: str | None) -> bytes:
    if file is not None:
        content = await read_upload_capped(file, _MAX_CONFIG_SIZE, None, what="Config")
    elif raw_text:
        content = raw_text.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="No config file or text provided")
    if len(content) > _MAX_CONFIG_SIZE:
        raise HTTPException(
            status_code=413, detail=f"Config exceeds the {_MAX_CONFIG_SIZE} byte limit"
        )
    if not content.strip():
        raise HTTPException(status_code=400, detail="Empty config")
    return content


def _detect_or_422(text: str) -> str:
    vendor = FirewallParserRegistry.detect_vendor(text)
    if not vendor:
        raise HTTPException(status_code=422, detail="Unrecognized firewall config format")
    return vendor


def _upload_summary(row: models.FirewallConfigUpload) -> dict:
    return {
        "id": row.id,
        "vendor": row.vendor,
        "hostname_in_config": row.hostname_in_config,
        "host_id": row.host_id,
        "rule_count": row.rule_count,
        "uploaded_by": row.uploaded_by,
        "ts": row.ts,
        "job_id": row.job_id,
    }


def _latest_upload_for_host(db: Session, pid: str, host_id: str, exclude_id: str = ""):
    q = db.query(models.FirewallConfigUpload).filter(
        models.FirewallConfigUpload.pid == pid,
        models.FirewallConfigUpload.host_id == host_id,
    )
    if exclude_id:
        q = q.filter(models.FirewallConfigUpload.id != exclude_id)
    return q.order_by(models.FirewallConfigUpload.ts.desc()).first()


@router.post("/api/projects/{pid}/firewall-configs/detect")
async def detect_firewall_config(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile | None, File()] = None,
    raw_text: Annotated[str | None, Form()] = None,
):
    check_pid_access(db, pid, user, _PERM)
    content = await _read_upload(file, raw_text)
    text = content.decode("utf-8", errors="replace")
    vendor = _detect_or_422(text)
    info = FirewallParserRegistry.get(vendor).get_vendor_info()
    return {"vendor": vendor, "display_name": info.display_name}


@router.post("/api/projects/{pid}/firewall-configs/preview")
async def preview_firewall_config(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile | None, File()] = None,
    raw_text: Annotated[str | None, Form()] = None,
):
    check_pid_access(db, pid, user, _PERM)
    content = await _read_upload(file, raw_text)
    text = content.decode("utf-8", errors="replace")
    vendor = _detect_or_422(text)
    parser = FirewallParserRegistry.get(vendor)
    parsed = parser.parse(text)

    # Dry run: enrich_project_from_config() only calls db.add() (ids are
    # app-generated via new_id(), not DB-assigned), so the rollback below
    # discards every pending object without ever touching committed state.
    try:
        result = enrich_project_from_config(db, pid, parsed, vendor)
        diff = {}
        if result.host_id:
            prev = _latest_upload_for_host(db, pid, result.host_id)
            if prev:
                diff = diff_parsed_configs(
                    prev.parsed_json or {}, parsed_config_to_safe_dict(parsed)
                )
    finally:
        db.rollback()

    public_ips = [i.ip_address for i in parsed.interfaces if i.is_public]

    return {
        "vendor": vendor,
        "display_name": parser.get_vendor_info().display_name,
        "hostname": parsed.system.hostname,
        "counts": {
            "interfaces": len(parsed.interfaces),
            "routes": len(parsed.routes),
            "acl_rules": len(parsed.acl_rules),
            "nat_rules": len(parsed.nat_rules),
            "vlans": len(parsed.vlans),
            "object_groups": len(parsed.object_groups),
            "local_users": len(parsed.local_users),
            "arp_entries": len(parsed.arp_entries),
            "dhcp_leases": len(parsed.dhcp_leases),
        },
        "public_ips": public_ips,
        "planned": {
            "host_created": result.host_created,
            "networks_created": result.networks_created,
            "networks_existing": result.networks_existing,
            "findings_created": result.findings_created,
            "findings_skipped": result.findings_skipped,
            "creds_created": result.creds_created,
            "creds_skipped": result.creds_skipped,
            "hosts_discovered": result.hosts_discovered,
            "hosts_enriched": result.hosts_enriched,
        },
        "diff": diff,
    }


@router.post("/api/projects/{pid}/firewall-configs/apply")
async def apply_firewall_config(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile | None, File()] = None,
    raw_text: Annotated[str | None, Form()] = None,
):
    check_pid_access(db, pid, user, _PERM)
    content = await _read_upload(file, raw_text)
    text = content.decode("utf-8", errors="replace")
    vendor = _detect_or_422(text)
    username = getattr(user, "username", "") or ""

    storage_key = await save_encrypted(pid, f"{new_id('fwcfg')}.cfg", content)

    upload = models.FirewallConfigUpload(
        id=new_id("fwc"),
        pid=pid,
        vendor=vendor,
        storage_key=storage_key,
        uploaded_by=username,
        ts=ts_now(),
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)

    job = queue_job(
        db,
        pid,
        "fwconfig",
        f"Firewall config: {vendor}",
        created_by=username,
        connector_key="fwconfig",
        operation="parse_apply",
        related_entity=("firewall_config_upload", upload.id),
        request_json={"upload_id": upload.id},
    )
    schedule_job_run(job.id, pid=pid, priority=5)

    log_event(
        db,
        pid,
        username,
        "import",
        "firewall_config_upload",
        f"Firewall config uploaded ({vendor}), queued for parsing",
        {"upload_id": upload.id, "job_id": job.id, "vendor": vendor},
    )

    return {"job_id": job.id, "upload_id": upload.id, "vendor": vendor}


@router.get("/api/projects/{pid}/firewall-configs")
def list_firewall_configs(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    host_id: str | None = None,
):
    check_pid_access(db, pid, user, _PERM)
    q = db.query(models.FirewallConfigUpload).filter(models.FirewallConfigUpload.pid == pid)
    if host_id:
        q = q.filter(models.FirewallConfigUpload.host_id == host_id)
    rows = q.order_by(models.FirewallConfigUpload.ts.desc()).all()
    return [_upload_summary(r) for r in rows]


@router.get("/api/projects/{pid}/firewall-configs/{upload_id}/diff")
def get_firewall_config_diff(
    pid: str,
    upload_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, _PERM)
    upload = (
        db.query(models.FirewallConfigUpload)
        .filter(models.FirewallConfigUpload.id == upload_id, models.FirewallConfigUpload.pid == pid)
        .first()
    )
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    prev = None
    if upload.host_id:
        prev = (
            db.query(models.FirewallConfigUpload)
            .filter(
                models.FirewallConfigUpload.pid == pid,
                models.FirewallConfigUpload.host_id == upload.host_id,
                models.FirewallConfigUpload.ts < upload.ts,
            )
            .order_by(models.FirewallConfigUpload.ts.desc())
            .first()
        )
    return diff_parsed_configs(prev.parsed_json if prev else {}, upload.parsed_json or {})
