"""
Scan snapshot creation and diffing.

When a scan finishes, we snapshot the host's observable state (ports,
services, OS, hostname, findings).  Later scans on the same host produce
a delta showing what changed between snapshots.
"""

from __future__ import annotations

from typing import Any

from .. import models
from ..core.utils import new_id, ts_now


def capture_host_snapshot(
    db,
    pid: str,
    host: models.Host,
    job_id: str = "",
    connector_key: str = "",
) -> models.ScanSnapshot:
    """Capture the *current* observable state of *host* into a new snapshot row."""
    findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.pid == pid,
            models.Finding.host_id == host.id,
            models.Finding.deleted_at.is_(None),
        )
        .all()
    )
    finding_list = [
        {
            "title": f.title,
            "severity": f.severity,
            "cve": f.cve or "",
            "cvss": f.cvss or "",
            "status": f.status,
            "source": f.source,
        }
        for f in findings
    ]
    snapshot_data: dict[str, Any] = {
        "ip": host.ip,
        "hostname": host.hostname,
        "os": host.os,
        "ports": sorted(host.ports or []),
        "services": sorted(host.services or []),
        "tags": sorted(host.tags or []),
        "domain": host.domain,
        "status": host.status,
        "findings": finding_list,
    }
    snap = models.ScanSnapshot(
        id=new_id("snap"),
        pid=pid,
        host_id=host.id,
        job_id=job_id,
        connector_key=connector_key,
        snapshot_json=snapshot_data,
        created_at=ts_now(),
    )
    db.add(snap)
    return snap


def capture_snapshot_for_ip(
    db,
    pid: str,
    ip: str,
    job_id: str = "",
    connector_key: str = "",
) -> models.ScanSnapshot | None:
    """Convenience: find host by IP and snapshot it."""
    host = (
        db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.ip == ip, models.Host.deleted_at.is_(None))
        .first()
    )
    if not host:
        return None
    return capture_host_snapshot(db, pid, host, job_id, connector_key)


def diff_snapshots(old: dict, new: dict) -> dict:
    """Pure-data diff between two snapshot_json dicts.

    Returns a dict with:
      added_ports, removed_ports, changed_ports (service changes)
      added_services, removed_services
      os_changed, hostname_changed, domain_changed
      new_findings, resolved_findings
      has_changes (bool)
    """
    old_ports = set(old.get("ports", []))
    new_ports = set(new.get("ports", []))

    old_services = set(old.get("services", []))
    new_services = set(new.get("services", []))

    added_ports = sorted(new_ports - old_ports)
    removed_ports = sorted(old_ports - new_ports)
    added_services = sorted(new_services - old_services)
    removed_services = sorted(old_services - new_services)

    os_changed = (old.get("os") or "") != (new.get("os") or "")
    hostname_changed = (old.get("hostname") or "") != (new.get("hostname") or "")
    domain_changed = (old.get("domain") or "") != (new.get("domain") or "")

    old_findings = _index_findings(old.get("findings", []))
    new_findings = _index_findings(new.get("findings", []))

    added_finding_keys = new_findings.keys() - old_findings.keys()
    removed_finding_keys = old_findings.keys() - new_findings.keys()

    new_findings_list = [new_findings[k] for k in sorted(added_finding_keys)]
    resolved_findings_list = [old_findings[k] for k in sorted(removed_finding_keys)]

    has_changes = bool(
        added_ports
        or removed_ports
        or added_services
        or removed_services
        or os_changed
        or hostname_changed
        or domain_changed
        or new_findings_list
        or resolved_findings_list
    )

    return {
        "added_ports": added_ports,
        "removed_ports": removed_ports,
        "added_services": added_services,
        "removed_services": removed_services,
        "os_changed": os_changed,
        "os_old": old.get("os", ""),
        "os_new": new.get("os", ""),
        "hostname_changed": hostname_changed,
        "hostname_old": old.get("hostname", ""),
        "hostname_new": new.get("hostname", ""),
        "domain_changed": domain_changed,
        "new_findings": new_findings_list,
        "resolved_findings": resolved_findings_list,
        "has_changes": has_changes,
    }


def _index_findings(findings: list[dict]) -> dict[str, dict]:
    """Index findings by a natural key (title + cve)."""
    result: dict[str, dict] = {}
    for f in findings:
        key = f"{f.get('title', '')}::{f.get('cve', '')}"
        if key not in result:
            result[key] = f
    return result


def get_host_scan_history(db, pid: str, host_id: str, limit: int = 20) -> list[models.ScanSnapshot]:
    """Return scan snapshots for *host_id*, newest first."""
    return (
        db.query(models.ScanSnapshot)
        .filter(
            models.ScanSnapshot.pid == pid,
            models.ScanSnapshot.host_id == host_id,
        )
        .order_by(models.ScanSnapshot.created_at.desc())
        .limit(limit)
        .all()
    )


def get_latest_diff_for_host(db, pid: str, host_id: str) -> dict | None:
    """Diff the two most recent snapshots for a host.

    Returns ``None`` if fewer than 2 snapshots exist.
    """
    history = get_host_scan_history(db, pid, host_id, limit=2)
    if len(history) < 2:
        return None
    new_snap, old_snap = history[0], history[1]
    diff = diff_snapshots(old_snap.snapshot_json, new_snap.snapshot_json)
    diff["new_snapshot_id"] = new_snap.id
    diff["old_snapshot_id"] = old_snap.id
    diff["new_scan_type"] = new_snap.connector_key
    diff["old_scan_type"] = old_snap.connector_key
    diff["new_scan_at"] = new_snap.created_at
    diff["old_scan_at"] = old_snap.created_at
    diff["new_job_id"] = new_snap.job_id
    diff["old_job_id"] = old_snap.job_id
    return diff
