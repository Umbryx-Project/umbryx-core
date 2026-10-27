"""
Shared scan helpers used by both synchronous scan endpoints (routers/scans.py)
and queued background jobs (core/job_runner.py).

Previously these were duplicated across the two modules.
"""

from __future__ import annotations

import ipaddress
import shlex

from .. import models
from ..core.key_management import encrypt_for_project
from ..core.utils import new_id

# ── Scope filtering ───────────────────────────────────────────────────
#
# Imports/scans must only ingest hosts whose IP falls inside the project's
# in-scope CIDR scopes. When a project defines no CIDR scope, filtering is a
# no-op (all hosts kept) to preserve behaviour for projects without scopes.


def load_scope_networks(db, pid: str) -> list:
    """Return in-scope CIDR networks for a project (empty = no CIDR scope defined)."""
    nets: list = []
    rows = (
        db.query(models.Scope)
        .filter(
            models.Scope.pid == pid,
            models.Scope.in_scope.is_(True),
            models.Scope.scope_type == "cidr",
        )
        .all()
    )
    for row in rows:
        val = (row.value or "").strip()
        if not val:
            continue
        try:
            nets.append(ipaddress.ip_network(val, strict=False))
        except ValueError:
            continue
    return nets


def ip_in_scope_networks(ip: str, networks: list) -> bool:
    """True if ip is inside any network. Empty networks → True (no filtering)."""
    if not networks:
        return True
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


def filter_parsed_hosts_in_scope(db, pid: str, parsed: list) -> tuple[list, int]:
    """Filter parsed host dicts to those in the project scope.

    Returns (kept_hosts, skipped_count). If the project has no CIDR scope
    defined, returns the input unchanged with skipped=0.
    """
    networks = load_scope_networks(db, pid)
    if not networks:
        return parsed, 0
    kept: list = []
    skipped = 0
    for h in parsed:
        if ip_in_scope_networks(h.get("ip", ""), networks):
            kept.append(h)
        else:
            skipped += 1
    return kept, skipped


# ── Port / service list merge ─────────────────────────────────────────
#
# Scan results merge into existing hosts across re-scans. A naive
# `list(set(a + b))` dedup has two visible defects:
#   1. set() loses order, so ports render in a shuffled, non-numeric order
#      that changes on every scan ("80, 3389, 8080, 22, 443").
#   2. service labels carry an optional version suffix ("22/ssh" vs
#      "22/ssh (OpenSSH 8.2p1)"), so a bare re-scan leaves BOTH entries and
#      the same port appears twice.
# These helpers dedup by port, keep numeric order, and prefer the richest
# label (the one carrying version/product info).


def _port_sort_key(entry):
    s = str(entry if entry is not None else "")
    head = s.split("/", 1)[0]
    rest = s[len(head):]
    try:
        return (0, int(head), rest)
    except ValueError:
        return (1, 0, s)


def merge_ports(existing: list | None, new: list | None) -> list:
    """Union of port strings ("22/tcp"), deduped, in numeric order."""
    seen: set = set()
    out: list = []
    for p in (existing or []) + (new or []):
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return sorted(out, key=_port_sort_key)


def merge_services(existing: list | None, new: list | None) -> list:
    """Union of service labels, deduped per port, keeping the richest label.

    Labels look like "22/ssh" or "22/ssh (OpenSSH 8.2p1)". Two labels for the
    same "port/service" base collapse to the longer (more informative) one.
    """
    best: dict = {}
    for s in (existing or []) + (new or []):
        if not s:
            continue
        base = str(s).split(" (", 1)[0]
        cur = best.get(base)
        if cur is None or len(str(s)) > len(str(cur)):
            best[base] = s
    return [best[b] for b in sorted(best, key=_port_sort_key)]


# ── Nmap host upsert ──────────────────────────────────────────────────


def nmap_upsert_host(db, pid: str, h: dict) -> tuple:
    existing = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h["ip"]).first()
    )
    if existing and existing.deleted_at:
        # Resurrect a soft-deleted host as a FRESH record: the operator
        # deleted the old data deliberately, so the new scan REPLACES
        # ports/services instead of merging — merging resurrected stale
        # ports from before the deletion (found live: delete hosts →
        # rescan one port → old ports reappeared). The row keeps its id
        # (notes/links stay attached), deleted_at clears.
        existing.deleted_at = None
        existing.ports = h["ports"] or []
        existing.services = h["services"] or []
        if h["hostname"] and not existing.hostname:
            existing.hostname = h["hostname"]
        existing.status = "up"
        existing.import_source = "nmap"
        return existing, True
    if existing:
        if h["ports"]:
            existing.ports = merge_ports(existing.ports, h["ports"])
        if h["services"]:
            existing.services = merge_services(existing.services, h["services"])
        if h["hostname"] and not existing.hostname:
            existing.hostname = h["hostname"]
        if h["os"] and not existing.os:
            existing.os = h["os"]
        existing.status = "up"
        if not existing.import_source:
            existing.import_source = "nmap"
        return existing, False
    host_obj = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=h["ip"],
        hostname=h.get("hostname", ""),
        os=h.get("os", "Linux"),
        status="up",
        ports=h["ports"],
        services=h["services"],
        tags=["nmap"],
        import_source="nmap",
    )
    db.add(host_obj)
    return host_obj, True


# ── CME/NetExec host + cred upsert ────────────────────────────────────


def cme_upsert_host(db, pid: str, h: dict) -> tuple:
    existing = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h["ip"]).first()
    )
    if existing and existing.deleted_at:
        # same resurrection semantics as nmap_upsert_host — see there
        existing.deleted_at = None
        existing.ports = h["ports"] or []
        existing.services = h["services"] or []
        existing.status = "up"
        return existing, True
    if existing:
        if h["hostname"] and not existing.hostname:
            existing.hostname = h["hostname"]
        existing.ports = merge_ports(existing.ports, h["ports"])
        existing.services = merge_services(existing.services, h["services"])
        if not existing.import_source:
            existing.import_source = "netexec"
        return existing, False
    hobj = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=h["ip"],
        hostname=h.get("hostname", ""),
        os="Windows",
        status="up",
        ports=h["ports"],
        services=h["services"],
        tags=["cme"],
        import_source="netexec",
    )
    db.add(hobj)
    return hobj, True


def cme_upsert_cred(db, pid: str, c: dict, best_domain: str, existing_keys: set) -> tuple:
    key = (c["username"], c.get("service", "smb"))
    if key in existing_keys:
        return None, False
    cobj = models.Cred(
        id=new_id("crd"),
        pid=pid,
        username=c["username"],
        secret=encrypt_for_project(db, pid, c.get("secret", "")),
        type=c.get("type", "plain"),
        service=c.get("service", "smb"),
        domain=best_domain,
        tags=["cme"],
    )
    db.add(cobj)
    existing_keys.add(key)
    return cobj, True


def cme_build_auth(payload: dict) -> str:
    if payload.get("hash"):
        return (
            f"-u {shlex.quote(payload.get('username') or '')} -H {shlex.quote(payload.get('hash'))}"
        )
    if payload.get("username") and payload.get("password"):
        return (
            f"-u {shlex.quote(payload.get('username'))} -p {shlex.quote(payload.get('password'))}"
        )
    if payload.get("username"):
        return f"-u {shlex.quote(payload.get('username'))}"
    return ""


def cme_process_hosts(db, pid: str, parsed_hosts: list) -> tuple:
    host_objects, discovered_domains = [], {}
    created = 0
    for h in parsed_hosts:
        if h.get("domain"):
            discovered_domains[h["ip"]] = h["domain"]
        hobj, was_created = cme_upsert_host(db, pid, h)
        if was_created:
            created += 1
        host_objects.append(hobj)
    return host_objects, discovered_domains, created


def cme_process_creds(
    db, pid: str, parsed_creds: list, best_domain: str, existing_keys: set
) -> tuple:
    cred_objects = []
    created = 0
    for c in parsed_creds:
        cobj, was_created = cme_upsert_cred(db, pid, c, best_domain, existing_keys)
        if was_created:
            created += 1
            cred_objects.append(cobj)
    return cred_objects, created


# ── Httpx host upsert ─────────────────────────────────────────────────


def httpx_upsert_host(db, pid: str, r: dict) -> models.Host:
    h_ip = r["host"]
    existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h_ip).first()
    if not existing:
        existing = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.hostname == h_ip)
            .first()
        )
    if existing:
        if r["port"] and r["port"] not in (existing.ports or []):
            existing.ports = list(set((existing.ports or []) + [r["port"]]))
        svc = "http" if r["port"] in (80, 8080) else "https"
        if svc not in (existing.services or []):
            existing.services = list(set((existing.services or []) + [svc]))
        return existing
    new_host = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=h_ip,
        hostname="",
        os="",
        status="up",
        ports=[r["port"]] if r["port"] else [],
        services=["http"] if r["port"] in (80, 8080) else ["https"],
        tags=["httpx"],
        import_source="httpx",
    )
    db.add(new_host)
    return new_host


# ── Ffuf severity + finding upsert ────────────────────────────────────


def ffuf_severity(status_code: int, path: str) -> str:
    severity = "info"
    if status_code in (200, 204):
        severity = "low"
    if path and any(
        kw in path.lower() for kw in ("admin", "config", "backup", "secret", ".env", "passwd")
    ):
        severity = "medium"
    return severity


def ffuf_upsert_finding(db, pid: str, r: dict, target_url: str, ts: str) -> bool:
    status_code = r.get("status") or 0
    path = r.get("input", {}).get("FUZZ") or r.get("url") or ""
    full_url = r.get("url") or f"{target_url}/{path}"
    length = r.get("length") or 0
    words = r.get("words") or 0
    existing = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.title == f"ffuf: {full_url}")
        .first()
    )
    if existing:
        return False
    db.add(
        models.Finding(
            id=new_id("fnd"),
            pid=pid,
            title=f"ffuf: {full_url}",
            severity=ffuf_severity(status_code, path),
            description=f"HTTP {status_code} — size {length} bytes / {words} words",
            proof=f"URL: {full_url}\nStatus: {status_code}\nSize: {length}\nWords: {words}",
            status="open",
            ts=ts,
        )
    )
    return True


# ── DonPAPI cred upsert + loot fetch ──────────────────────────────────


def donpapi_upsert_cred(db, pid: str, cred: dict, target: str, encrypt_fn) -> bool:
    existing = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == cred["username"],
            models.Cred.domain == (cred.get("domain") or ""),
            models.Cred.service == cred["service"],
        )
        .first()
    )
    if existing:
        return False
    db.add(
        models.Cred(
            id=new_id("c"),
            pid=pid,
            username=cred["username"],
            secret=encrypt_fn(cred["secret"]),
            type="plain",
            service=cred["service"],
            domain=cred.get("domain") or "",
            host=cred.get("host_hint") or target,
            tags=["donpapi", cred.get("kind") or ""],
        )
    )
    return True


def _donpapi_build_fetch_cmd(output_dir: str) -> str:
    safe_dir = shlex.quote(output_dir)
    return (
        f'tar -czf - -C "$(dirname {safe_dir})" '
        f'"$(basename {safe_dir})" 2>/dev/null | base64 -w 0'
    )


def _donpapi_create_loot_record(
    pid: str,
    target: str,
    target_host,
    tar_bytes: bytes,
    creds_created: int,
    job_or_id,
    job_id: str,
    db,
) -> str:
    from pathlib import Path as _Path

    from .. import schemas
    from ..core.config import UPLOAD_ROOT
    from ..core.events import bcast as _bcast
    from ..core.utils import ts_now

    loot_id = new_id("lt")
    loot_dir = UPLOAD_ROOT / pid / "loot"
    loot_dir.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = f"donpapi_{safe_target}.tar.gz"
    disk_path = _Path(loot_dir) / f"{loot_id}.tar.gz"
    disk_path.write_bytes(tar_bytes)
    _jid = job_id or (getattr(job_or_id, "id", "") if job_or_id else "")
    loot = models.Loot(
        id=loot_id,
        pid=pid,
        host_id=target_host.id if target_host else None,
        loot_type="file",
        value=filename,
        description=(
            f"DonPAPI dump artefacts from {target} "
            f"({len(tar_bytes)} bytes, {creds_created} cred(s))"
        ),
        source_path=f"/api/uploads/{pid}/loot/{loot_id}.tar.gz",
        filename=filename,
        content_type="application/gzip",
        file_size=len(tar_bytes),
        storage_path=str(disk_path),
        public_url=f"/api/uploads/{pid}/loot/{loot_id}.tar.gz",
        ts=ts_now(),
        job_id=_jid,
    )
    db.add(loot)
    db.flush()
    _bcast(pid, "loot", "create", schemas.Loot.model_validate(loot).model_dump())
    return loot_id


async def donpapi_fetch_loot(
    loop,
    ssh_config: dict,
    output_dir: str,
    pid: str,
    target: str,
    target_host,
    job_or_id,
    creds_created: int,
    db,
    *,
    cancel_token=None,
    job_actor: str = "",
    job_id: str = "",
) -> str:
    import base64 as _b64

    from ..core.events import log_event
    from ..core.ssh_exec import run_ssh_command
    from ..core.ssh_exec_cancellable import run_ssh_command_cancellable

    loot_id = ""
    try:
        fetch_cmd = _donpapi_build_fetch_cmd(output_dir)
        if cancel_token is not None:
            fetch_result = await loop.run_in_executor(
                None, lambda: run_ssh_command_cancellable(ssh_config, fetch_cmd, 120, cancel_token)
            )
        else:
            fetch_result = await loop.run_in_executor(
                None, lambda: run_ssh_command(ssh_config, fetch_cmd, 120)
            )
        b64_payload = (fetch_result.get("stdout") or "").strip()
        tar_bytes = b""
        if b64_payload:
            try:
                tar_bytes = _b64.b64decode(b64_payload)
            except Exception:
                tar_bytes = b""
        max_loot = 50 * 1024 * 1024
        if 0 < len(tar_bytes) <= max_loot:
            loot_id = _donpapi_create_loot_record(
                pid,
                target,
                target_host,
                tar_bytes,
                creds_created,
                job_or_id,
                job_id,
                db,
            )
    except Exception as exc:
        _actor = job_actor or (getattr(job_or_id, "created_by", "") if job_or_id else "")
        log_event(
            db,
            pid,
            _actor,
            "scan",
            "donpapi_loot_failed",
            f"DonPAPI loot fetch failed: {exc}",
            {"target": target, "error": str(exc)[:200]},
        )
    return loot_id
