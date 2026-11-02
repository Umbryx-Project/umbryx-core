from typing import Annotated

import httpx
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from ... import models, schemas
from ...core.deps import get_current_user, is_admin
from ...core.events import bcast, log_event
from ...core.job_tracker import finish_job, start_job
from ...core.key_management import encrypt_for_project
from ...core.logging_setup import get_logger
from ...core.permissions import PERM_HOSTS_READ
from ...core.utils import new_id, stable_edge_id, ts_now
from ...database import get_db
from ._adaptix import _adaptix_fetch_agent_tasks, _adaptix_fetch_bof_catalog, _adaptix_sync
from ._integrations import (
    _C2_SETTING_KEY,
    _MSG_INSUFFICIENT_PERMS,
    _MSG_INTEGRATION_NOT_FOUND,
    _c2_owns_host_status,
    _can_manage_integration,
    _has_live_session_signal,
    _load_integrations,
    _require_c2,
    _safe_integration,
    _status_from_c2_host,
    _visible_integrations_for_pid,
    router,
)
from ._mythic import _mythic_fetch_agent_tasks, _mythic_sync
from ._sliver import _sliver_fetch_agent_tasks, _sliver_sync

logger = get_logger(__name__)

_CONNECTORS = {
    "sliver": _sliver_sync,
    "adaptix": _adaptix_sync,
    "mythic": _mythic_sync,
}


@router.post(
    "/{iid}/test",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)
async def test_connection(
    iid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if not _can_manage_integration(db, user, cfg):
        raise HTTPException(403, _MSG_INSUFFICIENT_PERMS)
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")

    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise HTTPException(400, f"Unsupported C2 type: {cfg['type']}")

    try:
        data = await connector(cfg)
        if data.get("error"):
            raise HTTPException(400, f"C2 test failed: {data['error']}")
        return {
            "ok": True,
            "hosts_found": len(data.get("hosts") or []),
            "creds_found": len(data.get("creds") or []),
        }
    except HTTPException:
        raise
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")


async def _do_project_sync(
    cfg: dict, pid: str, db: Session, iid: str | None = None, created_by: str = "auto"
) -> dict:
    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise ValueError(f"Unsupported C2 type: {cfg['type']}")

    label = cfg.get("label") or cfg.get("type", "c2")
    job = start_job(
        db,
        pid,
        "c2_sync",
        f"C2 Sync: {label}",
        target=cfg.get("url", ""),
        created_by=created_by,
        connector_key="c2_integration",
        operation="sync",
        related_entity=("project", pid),
        request_json={
            "iid": iid,
            "type": cfg.get("type"),
            "url": cfg.get("url"),
            "project_id": pid,
        },
    )

    try:
        result = await _do_project_sync_inner(cfg, pid, db, iid)
    except Exception as e:
        finish_job(db, job, status="failed", error_output=str(e))
        raise

    finish_job(
        db,
        job,
        status="done",
        output=f"hosts_found={result['hosts_found']} created={result['hosts_created']} updated={result['hosts_updated']} creds_created={result['creds_created']}",
        result=result,
    )
    return result


def _c2_update_host_status(host, source: str, h: dict) -> None:
    derived_status = _status_from_c2_host("", h)
    if _c2_owns_host_status(host, source):
        if derived_status:
            host.status = derived_status
    else:
        next_status = _status_from_c2_host(host.status or "", h)
        if next_status:
            host.status = next_status


def _c2_append_host_note(db, pid: str, host_id: str, new_notes: str, source: str) -> None:
    """Append C2-sourced enrichment text to a per-host, per-source auto-note.

    Host.notes (a single free-text column) was replaced by full Notes
    attached via Note.host_id — this reproduces the old "append with a
    `---` separator, skip if already present" behavior against a
    find-or-create Note instead, so repeated syncs keep accumulating into
    one running log per (host, source) rather than spawning a new note
    every sync.
    """
    if not new_notes:
        return
    title = f"C2 sync notes ({source})"
    note = (
        db.query(models.Note)
        .filter(
            models.Note.pid == pid,
            models.Note.host_id == host_id,
            models.Note.title == title,
            models.Note.deleted_at.is_(None),
        )
        .first()
    )
    if note:
        if new_notes in (note.content or ""):
            return
        note.content = (note.content or "").rstrip() + "\n\n---\n" + new_notes
        note.ts = ts_now()
        note.version += 1
    else:
        db.add(
            models.Note(
                id=new_id("n"),
                pid=pid,
                host_id=host_id,
                title=title,
                phase="recon",
                tags=["c2", "auto", source],
                content=new_notes,
                ts=ts_now(),
            )
        )


def _c2_enrich_host(
    db,
    pid: str,
    host,
    hostname: str,
    domain: str,
    os_clean: str,
    new_notes: str,
    source: str,
    h: dict,
) -> None:
    if hostname and not host.hostname:
        host.hostname = hostname
    if domain and not host.domain:
        host.domain = domain
    if os_clean and os_clean != "Unknown" and (not host.os or host.os in ("Linux", "Unknown", "")):
        host.os = os_clean
    _c2_update_host_status(host, source, h)
    cur_tags = host.tags or []
    _c2_append_host_note(db, pid, host.id, new_notes, source)
    if source not in cur_tags:
        host.tags = list(cur_tags) + [source]
    if not host.import_source:
        host.import_source = source


def _c2_upsert_session_cred(db, pid: str, ip: str, username: str, source: str) -> int:
    username = (username or "").strip()
    if not username:
        return 0
    cred_domain = ""
    uname = username
    if "\\" in username:
        parts = username.split("\\", 1)
        cred_domain, uname = parts[0], parts[1]
    elif "@" in username:
        parts = username.split("@", 1)
        uname, cred_domain = parts[0], parts[1]
    existing_cred = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == cred_domain,
            models.Cred.host == ip,
        )
        .first()
    )
    if existing_cred:
        return 0
    from ...core.db_upsert import try_insert_or_get

    new_cred = models.Cred(
        id=new_id("crd"),
        pid=pid,
        username=uname,
        domain=cred_domain,
        secret="",
        type="plain",
        service="os",
        host=ip,
        tags=["c2", source],
    )
    _, was_created = try_insert_or_get(
        db,
        new_cred,
        requery=lambda: db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == cred_domain,
            models.Cred.host == ip,
        )
        .first(),
    )
    return 1 if was_created else 0


def _c2_sync_one_host(db, pid: str, h: dict, source: str):
    ip = h.get("ip", "").strip()
    hostname = h.get("hostname", "").strip()
    if not ip and not hostname:
        return None, 0, 0, 0
    if not ip:
        ip = hostname
    os_clean = (h.get("os") or "").strip() or "Unknown"
    domain = (h.get("domain") or "").strip()
    new_notes = (h.get("note") or "").strip()
    existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
    if existing:
        # A host the operator deleted but whose agent is STILL LIVE must
        # come back: the session is real and active, a tombstone here
        # made the host vanish from the Hosts tab while the network map
        # kept showing the node (reported as "host with agent disappears").
        resurrected = False
        if existing.deleted_at and _has_live_session_signal(h):
            existing.deleted_at = None
            resurrected = True
        _c2_enrich_host(db, pid, existing, hostname, domain, os_clean, new_notes, source, h)
        cred_delta = _c2_upsert_session_cred(db, pid, ip, h.get("username", ""), source)
        return existing, 1 if resurrected else 0, 1, cred_delta
    if not h.get("alive", True):
        return None, 0, 0, 0
    from ...core.db_upsert import try_insert_or_get

    new_host = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=ip,
        hostname=hostname,
        os=os_clean,
        domain=domain,
        status=_status_from_c2_host("", h) or "up",
        tags=["c2", source],
        import_source=source,
    )
    row, was_created = try_insert_or_get(
        db,
        new_host,
        requery=lambda: db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.ip == ip)
        .first(),
    )
    if was_created:
        _c2_append_host_note(db, pid, row.id, new_notes, source)
    else:
        _c2_enrich_host(db, pid, row, hostname, domain, os_clean, new_notes, source, h)
    cred_delta = _c2_upsert_session_cred(db, pid, ip, h.get("username", ""), source)
    created = 1 if was_created else 0
    updated = 0 if was_created else 1
    return row, created, updated, cred_delta


def _c2_upsert_harvested_cred(db, pid: str, c: dict, source: str) -> bool:
    uname = (c.get("username") or "").strip()
    if not uname:
        return False
    domain = (c.get("realm") or "").strip()
    existing = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == domain,
        )
        .first()
    )
    if existing:
        return False
    db.add(
        models.Cred(
            id=new_id("crd"),
            pid=pid,
            username=uname,
            secret=encrypt_for_project(db, pid, c.get("secret", "")),
            type=c.get("type", "plain"),
            domain=domain,
            service=c.get("service", ""),
            host=c.get("host", ""),
            tags=["c2", source],
        )
    )
    return True


def _c2_entry_node_id(db, pid: str, cfg: dict, all_nodes_raw) -> str | None:
    """Network node of the C2's PUBLIC entry — the redirector when the C2
    sits behind a reverse tunnel (beacons never touch the C2 host
    directly), else the C2 host itself. None → caller falls back."""
    try:
        from ...models.infra_v2 import InfraProvider, ServiceLink, StackService

        svc_id = cfg.get("service_id")
        if not svc_id:
            return None
        svc = db.query(StackService).get(svc_id)
        if not svc:
            return None

        # redirector fronting this C2 (reverse_tunnel link)
        lnk = (
            db.query(ServiceLink)
            .filter(ServiceLink.to_service_id == svc.id, ServiceLink.link_type == "reverse_tunnel")
            .first()
        )
        entry_svc = None
        if lnk:
            entry_svc = db.query(StackService).get(lnk.from_service_id)
        if entry_svc is None:
            entry_svc = svc  # direct exposure: the C2 host is the entry

        prov = db.query(InfraProvider).get(entry_svc.provider_id) if entry_svc.provider_id else None
        entry_ip = (prov.public_host or prov.host or "") if prov else ""
        if not entry_ip:
            return None

        # match a node: by the entry host's registered host_id, else by ip
        from ...models import Host

        entry_host = (
            db.query(Host)
            .filter(Host.pid == pid, Host.ip == entry_ip, Host.is_attacker.is_(True))
            .first()
        )
        if entry_host:
            for n in all_nodes_raw:
                if n.host_id == entry_host.id:
                    return n.id
        for n in all_nodes_raw:
            if (n.ip or "") == entry_ip:
                return n.id
    except Exception:  # noqa: BLE001
        return None
    return None


def _c2_upsert_session_edges(
    db,
    pid: str,
    source: str,
    ts: str,
    live_host_ids: set,
    stale_host_ids: set,
    cfg: dict | None = None,
) -> bool:
    """Write c2_session edges (attacker → target) directly into the network graph.

    This runs on every C2 sync so the graph stays live without requiring a manual
    Smart Build.  Edges use source="c2_sync" so Smart Build won't confuse them with
    host_activity-derived edges and can safely overwrite/merge them.
    """
    try:
        from ...core.network_data import delete_edge, upsert_edge

        network = db.query(models.Network).filter(models.Network.pid == pid).first()
        if not network:
            return

        # Map host_id → node_id
        all_nodes_raw = (
            db.query(models.NetworkNode).filter(models.NetworkNode.network_id == network.id).all()
        )
        attacker_nids = [n.id for n in all_nodes_raw if n.is_attacker]
        if not attacker_nids:
            attacker_hosts = (
                db.query(models.Host)
                .filter(models.Host.pid == pid, models.Host.is_attacker.is_(True))
                .all()
            )
            ah_ids = {h.id for h in attacker_hosts}
            attacker_nids = [n.id for n in all_nodes_raw if n.host_id in ah_ids]
        if not attacker_nids:
            return
        # The session edge must originate at the C2's PUBLIC entry (the
        # redirector for tunneled C2s) — attacker_nids[0] picked an
        # arbitrary attacker host and the edge flipped between syncs,
        # drawing impossible direct agent→C2-host connections.
        from_nid = _c2_entry_node_id(db, pid, cfg or {}, all_nodes_raw) or attacker_nids[0]
        hid_to_nid = {n.host_id: n.id for n in all_nodes_raw if n.host_id}

        # Existing edge ids, loaded ONCE: the sync must be change-aware.
        # It runs every ~5 minutes and previously re-upserted every edge
        # (ts-only refresh) and ALWAYS broadcast edges_updated, so every
        # connected client refetched the whole network list each cycle,
        # and any position divergence between a client draft and the
        # server surfaced as a visible node jump.
        existing_edge_ids = {
            e.id
            for e in db.query(models.NetworkEdge)
            .filter(models.NetworkEdge.network_id == network.id)
            .with_entities(models.NetworkEdge.id)
        }
        graph_changed = False

        # drop session edges written earlier from a WRONG attacker node
        # (source/type are COLUMNS — extra_json never had them, so the
        # first cleanup attempt matched nothing and stale edges survived)
        try:
            wrong = (
                db.query(models.NetworkEdge)
                .filter(
                    models.NetworkEdge.network_id == network.id,
                    models.NetworkEdge.source == "c2_sync",
                    models.NetworkEdge.type == "c2_session",
                )
                .all()
            )
            for e in wrong:
                if e.from_node_id != from_nid:
                    delete_edge(e.id, db)
                    graph_changed = True
        except Exception:  # noqa: BLE101
            pass

        # Infrastructure edge: redirector → C2 host (the chain the
        # beacons actually traverse). Without it the map shows an
        # island redirector with a session edge but no visible path
        # back to the C2 infrastructure.
        entry_nid = from_nid  # the redirector (or C2 host if direct)
        c2_nid = None
        if cfg and cfg.get("service_id"):
            from ...models.infra_v2 import StackService as SS

            c2_svc = db.query(SS).get(cfg["service_id"])
            if c2_svc and c2_svc.provider_id:
                from ...models.infra_v2 import InfraProvider

                c2_prov = db.query(InfraProvider).get(c2_svc.provider_id)
                c2_ip = (c2_prov.public_host or c2_prov.host or "") if c2_prov else ""
                if not c2_ip and c2_svc.connection_url:
                    # k8s providers keep the node IP in the connection_url
                    # (https://172.16.100.188:31961) — the host column is empty
                    import re as _re2

                    m = _re2.search(r"https?://([0-9.]+)", c2_svc.connection_url)
                    if m:
                        c2_ip = m.group(1)
                if c2_ip:
                    from ...models import Host

                    c2_host = (
                        db.query(Host)
                        .filter(Host.pid == pid, Host.ip == c2_ip, Host.is_attacker.is_(True))
                        .first()
                    )
                    if c2_host:
                        c2_nid = hid_to_nid.get(c2_host.id)
                    if not c2_nid:
                        for n in all_nodes_raw:
                            if (n.ip or "") == c2_ip:
                                c2_nid = n.id
                                break
                    if not c2_nid:
                        # the C2's provider IP (e.g. k3s node) may not have
                        # a Host in the graph — fall back to an attacker
                        # node in the same /24 (the infra machine that
                        # hosts the cluster)
                        import ipaddress as _ipa

                        try:
                            c2_net = _ipa.ip_network(f"{c2_ip}/24", strict=False)
                            for n in all_nodes_raw:
                                n_ip = n.ip or ""
                                if n_ip and n.is_attacker:
                                    try:
                                        if _ipa.ip_address(n_ip) in c2_net:
                                            c2_nid = n.id
                                            break
                                    except ValueError:
                                        continue
                        except ValueError:
                            pass
        if c2_nid and entry_nid != c2_nid:
            infra_edge_id = stable_edge_id(entry_nid, c2_nid, "c2_sync", "c2_infra")
            if infra_edge_id in existing_edge_ids:
                infra_edge_id = None  # already drawn — refresh would be churn
            else:
                graph_changed = True
        else:
            infra_edge_id = None
        if infra_edge_id:
            upsert_edge(
                network.id,
                pid,
                {
                    "id": infra_edge_id,
                    "from": entry_nid,
                    "to": c2_nid,
                    "type": "c2_infra",
                    "label": "c2 tunnel",
                    "confidence": 1.0,
                    "source": "c2_sync",
                    "reason": f"Redirector tunnels to C2 host ({source})",
                    "state": "observed",
                    "verified": True,
                    "is_manual": False,
                    "ts": ts,
                },
                db,
            )

        # Add edges for live sessions (creation only: an existing edge is
        # NOT rewritten, so a long-running session generates no churn)
        for host_id in live_host_ids:
            target_nid = hid_to_nid.get(host_id)
            if not target_nid or target_nid == from_nid:
                continue
            edge_id = stable_edge_id(from_nid, target_nid, "c2_sync", "c2_session")
            if edge_id in existing_edge_ids:
                continue
            graph_changed = True
            upsert_edge(
                network.id,
                pid,
                {
                    "id": edge_id,
                    "from": from_nid,
                    "to": target_nid,
                    "type": "c2_session",
                    "label": "c2 session",
                    "confidence": 1.0,
                    "source": "c2_sync",
                    "reason": f"Live {source} C2 session (synced {ts})",
                    "state": "observed",
                    "verified": True,
                    "is_manual": False,
                    "ts": ts,
                },
                db,
            )

        # Remove edges for hosts that no longer have active sessions
        for host_id in stale_host_ids:
            target_nid = hid_to_nid.get(host_id)
            if not target_nid:
                continue
            edge_id = stable_edge_id(from_nid, target_nid, "c2_sync", "c2_session")
            if edge_id in existing_edge_ids:
                delete_edge(edge_id, db)
                graph_changed = True

        db.flush()
        if graph_changed:
            bcast(pid, "network", "edges_updated", {"source": "c2_sync", "ts": ts})
        return graph_changed
    except Exception as exc:
        logger.warning(
            "c2 edge sync failed for pid=%s — network graph may not reflect current C2 session state: %s",
            pid,
            exc,
        )


def _c2_record_c2_activities(
    db, pid: str, cfg: dict, source: str, ts: str, session_host_raw: list, host_objects: list
) -> None:
    session_host_ids = {hobj.id for hobj, _ in session_host_raw}
    for hobj, _h in session_host_raw:
        try:
            existing_act = (
                db.query(models.HostActivity)
                .filter(
                    models.HostActivity.pid == pid,
                    models.HostActivity.host_id == hobj.id,
                    models.HostActivity.activity_type == "c2",
                )
                .first()
            )
            if existing_act:
                existing_act.ts = ts
                existing_act.summary = f"Active {source} session (synced {ts})"
            else:
                db.add(
                    models.HostActivity(
                        id=new_id("ha"),
                        pid=pid,
                        host_id=hobj.id,
                        title=f"C2 session [{cfg['name']}]",
                        activity_type="c2",
                        summary=f"Active {source} session (synced {ts})",
                        status="done",
                        ts=ts,
                    )
                )
        except Exception as e:
            logger.info(
                "failed to record C2 session activity for host %s (pid=%s): %s", hobj.id, pid, e
            )
    stale_host_ids = {hobj.id for hobj in host_objects} - session_host_ids
    if stale_host_ids:
        db.query(models.HostActivity).filter(
            models.HostActivity.pid == pid,
            models.HostActivity.host_id.in_(stale_host_ids),
            models.HostActivity.activity_type == "c2",
        ).delete(synchronize_session=False)


def _c2_update_last_sync(db, iid: str | None, ts: str) -> None:
    if not iid:
        return
    from sqlalchemy.orm.attributes import flag_modified

    integrations_raw = (
        db.query(models.GlobalSetting).filter(models.GlobalSetting.key == _C2_SETTING_KEY).first()
    )
    if not integrations_raw:
        return
    raw_list = integrations_raw.value if isinstance(integrations_raw.value, list) else []
    hit = False
    for item in raw_list:
        if item.get("id") == iid:
            item["last_sync"] = ts
            hit = True
            break
    if not hit:
        return
    # JSONB in-place mutation is invisible to the unit of work — without
    # flag_modified the UPDATE never fires and last_sync stayed None forever
    # (found live: the auto-sync re-fired every minute).
    integrations_raw.value = raw_list
    flag_modified(integrations_raw, "value")
    db.commit()


def _broadcast_synced_hosts(db: "Session", pid: str, host_objects: list) -> None:
    for hobj in host_objects:
        try:
            db.refresh(hobj)
            bcast(pid, "host", "upsert", schemas.Host.model_validate(hobj).model_dump())
        except Exception as e:
            logger.info("failed to broadcast synced host %s (pid=%s): %s", hobj.id, pid, e)


def _trigger_topology_rebuild_if_needed(pid: str, db: "Session", created_hosts: int) -> None:
    if created_hosts <= 0:
        return
    try:
        from ..topology import _run_auto_build

        _run_auto_build(pid, db)
    except Exception as e:
        logger.warning("C2 sync: topology auto-build failed for %s: %s", pid, e)


async def _do_project_sync_inner(cfg: dict, pid: str, db: Session, iid: str | None = None) -> dict:
    connector = _CONNECTORS.get(cfg["type"])
    if connector is None:
        raise HTTPException(400, f"Unsupported C2 type: {cfg.get('type')}")
    data = await connector(cfg)
    if data.get("error"):
        raise HTTPException(400, f"C2 sync failed: {data['error']}")
    ts = ts_now()
    created_hosts, updated_hosts, created_creds = 0, 0, 0
    source = cfg["type"]
    host_objects = []
    session_host_raw: list[tuple] = []

    for h in data.get("hosts", []):
        host_obj, c, u, cred_delta = _c2_sync_one_host(db, pid, h, source)
        if host_obj is None:
            continue
        created_hosts += c
        updated_hosts += u
        created_creds += cred_delta
        host_objects.append(host_obj)
        if _has_live_session_signal(h):
            session_host_raw.append((host_obj, h))

    for c in data.get("creds", []):
        if _c2_upsert_harvested_cred(db, pid, c, source):
            created_creds += 1

    _c2_record_c2_activities(db, pid, cfg, source, ts, session_host_raw, host_objects)

    live_ids = {hobj.id for hobj, _ in session_host_raw}
    stale_ids = {hobj.id for hobj in host_objects} - live_ids
    edges_changed = (
        _c2_upsert_session_edges(db, pid, source, ts, live_ids, stale_ids, cfg=cfg) or False
    )

    # Steady-state auto-syncs (nothing created, nothing changed) must not
    # pollute the project timeline — a 5-minute cycle used to add a "C2
    # sync: 0 new hosts" line every run and bury the real activity.
    if created_hosts > 0 or created_creds > 0 or edges_changed:
        log_event(
            db,
            pid,
            None,
            "c2",
            "sync",
            f"C2 sync [{cfg['name']}]: {created_hosts} new hosts, {updated_hosts} updated, {created_creds} creds",
            {"source": source, "integration": cfg["name"]},
        )
    db.commit()

    _c2_update_last_sync(db, iid, ts)

    _broadcast_synced_hosts(db, pid, host_objects)
    _trigger_topology_rebuild_if_needed(pid, db, created_hosts or len(session_host_raw))

    return {
        "ok": True,
        "source": source,
        "hosts_found": len(data.get("hosts") or []),
        "hosts_created": created_hosts,
        "hosts_updated": updated_hosts,
        "creds_found": len(data.get("creds") or []),
        "creds_created": created_creds,
    }


@router.post(
    "/{iid}/sync/{pid}",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)
async def sync_to_project(
    iid: str,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if not is_admin(user):
        from ...core.access import check_pid_access

        check_pid_access(db, pid, user, "hosts.create")
    try:
        return await _do_project_sync(cfg, pid, db, iid=iid, created_by=user.username)
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")


@router.get(
    "/for-project/{pid}",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)
def list_for_project(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    integrations = _load_integrations(db)
    visible = [_safe_integration(i) for i in _visible_integrations_for_pid(integrations, pid)]
    return visible


@router.get(
    "/{iid}/bofs/{pid}",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)
async def list_bofs_for_project(
    iid: str,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    cfg = next(
        (
            i
            for i in _visible_integrations_for_pid(_load_integrations(db), pid)
            if i.get("id") == iid
        ),
        None,
    )
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if cfg.get("type") != "adaptix":
        return []
    try:
        return await _adaptix_fetch_bof_catalog(cfg)
    except Exception as e:
        logger.warning("Adaptix BOF catalog failed for %s: %s", iid, e)
        return []


@router.get(
    "/agent-tasks/{pid}",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)
async def get_agent_tasks(
    pid: str,
    integration_id: str,
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: int = 30,
):
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    if not integration_id.strip() or not agent_id.strip():
        raise HTTPException(400, "integration_id and agent_id are required")
    cfg = next(
        (
            i
            for i in _visible_integrations_for_pid(_load_integrations(db), pid)
            if i.get("id") == integration_id
        ),
        None,
    )
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    c2_type = (cfg.get("type") or "").lower()
    try:
        if c2_type == "adaptix":
            return await _adaptix_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        if c2_type == "mythic":
            return await _mythic_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        if c2_type == "sliver":
            return await _sliver_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        raise HTTPException(400, f"Agent task history not supported for C2 type {c2_type!r}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Failed to fetch agent tasks: {e}")
