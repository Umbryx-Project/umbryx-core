"""Continuous attack-surface monitoring engine.

A SurfaceWatch run reuses the platform's standard scan pipeline (attacker
SSH transport -> nmap -> parse -> Host graph upsert) and adds the two
pieces that pipeline never had: a periodic trigger and a diff of what the
scan changed versus the stored baseline, with notifications on surface
growth.

Deliberately cheap: one nmap sweep per interval over the project scope,
no cred validation, no exploitation — this is monitoring, not another
engagement workflow. Ops people should be able to leave it running for
months on a client perimeter between engagements.
"""

from __future__ import annotations

import logging
import threading

from sqlalchemy.orm import Session

from ..models import Host, Scope
from ..models.surface_watch import SurfaceWatch
from .utils import ts_now

logger = logging.getLogger(__name__)


def capture_state(db: Session, pid: str) -> dict:
    """Compress the project's live hosts into a diffable state."""
    hosts = (
        db.query(Host)
        .filter(Host.pid == pid, Host.deleted_at.is_(None), Host.is_attacker.is_(False))
        .all()
    )
    return {
        h.ip: {
            "hostname": h.hostname or "",
            "status": h.status,
            "ports": sorted(h.ports or []),
            "services": sorted(h.services or []),
        }
        for h in hosts
        if h.ip
    }


def diff_states(pre: dict, post: dict) -> dict:
    """Surface-growth diff. Only changes an operator must know about:

    - new hosts (by IP)
    - new open ports on known hosts
    - host status flips (up <-> down)
    - new services on known hosts

    Port/service *removals* and hostname edits are not surfaced — the
    platform is a red-team tool; a closed port is not an alert.
    """
    new_hosts = []
    new_ports = []
    status_changes = []
    new_services = []

    for ip, after in post.items():
        before = pre.get(ip)
        if before is None:
            new_hosts.append({"ip": ip, "hostname": after["hostname"], "ports": after["ports"]})
            continue
        added_ports = sorted(set(after["ports"]) - set(before["ports"]))
        if added_ports:
            new_ports.append({"ip": ip, "ports": added_ports})
        if before["status"] != after["status"]:
            status_changes.append(
                {"ip": ip, "from": before["status"], "to": after["status"]}
            )
        added_services = sorted(set(after["services"]) - set(before["services"]))
        if added_services:
            new_services.append({"ip": ip, "services": added_services})

    return {
        "new_hosts": new_hosts,
        "new_ports": new_ports,
        "status_changes": status_changes,
        "new_services": new_services,
    }


def diff_has_changes(diff: dict) -> bool:
    return bool(diff["new_hosts"] or diff["new_ports"] or diff["new_services"])


def resolve_targets(db: Session, pid: str, watch: SurfaceWatch) -> str:
    if watch.targets.strip():
        return watch.targets.strip()
    rows = db.query(Scope).filter(Scope.pid == pid).all()
    cidrs = [r.value for r in rows if getattr(r, "value", "") and "/" in (r.value or "")]
    return " ".join(cidrs)


def _notify_change(db: Session, pid: str, watch: SurfaceWatch, diff: dict) -> None:
    from .events import log_event
    from .notify import push_to_project_members

    parts = []
    if diff["new_hosts"]:
        ips = ", ".join(h["ip"] for h in diff["new_hosts"][:5])
        more = len(diff["new_hosts"]) - 5
        parts.append(f"new host(s): {ips}" + (f" +{more}" if more > 0 else ""))
    if diff["new_ports"]:
        for entry in diff["new_ports"][:5]:
            parts.append(f"{entry['ip']}: new port(s) {', '.join(entry['ports'])}")
    if diff["new_services"]:
        for entry in diff["new_services"][:3]:
            parts.append(f"{entry['ip']}: new service(s) {', '.join(entry['services'])}")

    push_to_project_members(
        db,
        pid=pid,
        type="warning",
        title=f"[{watch.name}] Attack surface changed",
        body="; ".join(parts)[:900],
    )
    log_event(
        db,
        pid,
        "surface-watch",
        "watch",
        "change",
        f"Surface change detected by '{watch.name}': {'; '.join(parts)}"[:500],
        {"watch_id": watch.id, "diff": diff},
    )


def _run_watch_sync(watch_id: str) -> None:
    """One full watch run, in its own thread (SSH scans take minutes).

    Own session: the scheduler loop must never block on scan I/O.
    """
    from ..database import SessionLocal

    db = SessionLocal()
    try:
        watch = db.query(SurfaceWatch).get(watch_id)
        if not watch or not watch.enabled:
            return
        pre = capture_state(db, watch.pid)
        targets = resolve_targets(db, watch.pid, watch)
        if not targets:
            watch.state = "idle"
            watch.last_run_at = ts_now()
            db.commit()
            return

        from ..routers.scans import _parse_nmap_xml  # reuse the scan pipeline, don't copy it
        from .attacker_transport import resolve_scan_target
        from .intensity import resolve_nmap_flags
        from .job_tracker import start_job
        from .scan_helpers import filter_parsed_hosts_in_scope, nmap_upsert_host
        from .ssh_exec import run_ssh_command, safe_shell_field

        ssh_config = resolve_scan_target(watch.pid, None, db, targets.split()[0])
        scan_flags = resolve_nmap_flags(watch.intensity_profile or "normal", None)
        # Security audit 2026-10-07 (finding 2): watch.targets is stored user
        # input (creating a watch needs only hosts.create, not an exec
        # permission) and this command is re-executed by the scheduler on
        # every tick — it was the only nmap call site not routing the target
        # through safe_shell_field (cf. routers/scans.py, core/job_runner.py).
        cmd = (
            f"nmap {safe_shell_field(scan_flags)} -oX - {safe_shell_field(targets)} 2>/dev/null"
        )

        job = start_job(
            db,
            watch.pid,
            "nmap",
            f"[watch] {watch.name}: {targets[:80]}",
            target=targets[:200],
            command=cmd,
            created_by="surface-watch",
            connector_key="nmap",
            operation="scan",
            related_entity=("surface_watch", watch.id),
        )
        watch.last_job_id = job.id
        db.commit()

        result = run_ssh_command(ssh_config, cmd, 900)
        parsed = _parse_nmap_xml(result.get("stdout", ""))
        parsed, _oos = filter_parsed_hosts_in_scope(db, watch.pid, parsed)
        for h in parsed:
            nmap_upsert_host(db, watch.pid, h)
        db.commit()

        post = capture_state(db, watch.pid)
        diff = diff_states(pre, post)
        watch.baseline_json = post
        watch.last_diff_json = diff
        watch.last_run_at = ts_now()
        watch.state = "idle"
        if diff_has_changes(diff):
            watch.last_change_at = ts_now()
            _notify_change(db, watch.pid, watch, diff)
        db.commit()
    except Exception as exc:
        logger.error("surface watch %s run failed: %s", watch_id, exc)
        try:
            watch = db.query(SurfaceWatch).get(watch_id)
            if watch:
                watch.state = "idle"
                watch.last_run_at = ts_now()
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def fire_due_watches(db: Session, now) -> int:
    """Start every enabled watch whose interval has elapsed. Returns the
    number of runs started.

    HA-safe the same way the scheduled-playbook loop is: last_run_at is
    written before the thread starts, so a second instance's next tick
    sees the updated timestamp and skips the window.
    """
    from datetime import datetime

    started = 0
    watches = db.query(SurfaceWatch).filter(SurfaceWatch.enabled.is_(True)).all()
    for watch in watches:
        if watch.state == "running":
            continue
        last = None
        if watch.last_run_at:
            try:
                last = datetime.fromisoformat(watch.last_run_at.replace("Z", "+00:00"))
            except ValueError:
                try:
                    last = datetime.strptime(watch.last_run_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    last = None
        due_at = last.timestamp() if last else 0
        if now.timestamp() - due_at < watch.interval_minutes * 60:
            continue

        watch.state = "running"
        watch.last_run_at = ts_now()  # claim the window before spawning
        db.commit()
        threading.Thread(target=_run_watch_sync, args=(watch.id,), daemon=True).start()
        started += 1
    return started
