from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import models
from ..core.access import (
    check_object_access,
    check_pid_access,
    require_attack_path_in_project,
)
from ..core.attack_metrics import calculate_path_risk
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.permissions import (
    PERM_ATTACK_PATHS_READ,
    PERM_ATTACK_PATHS_UPDATE,
    PERM_LINKS_MANAGE,
    PERM_LINKS_READ,
)
from ..core.utils import new_id, ts_now
from ..database import get_db
from ..schemas import attack_graph as sch

router = APIRouter(tags=["attack-path-editor"])


def _get_path_pid(db, path_id):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    return ap.pid if ap else None


# ── Nodes ──────────────────────────────────────────────────────────────


@router.get("/api/attack-path-nodes", response_model=list[sch.AttackPathNode])
def list_nodes(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    path_id: str | None = None,
    pid: str | None = None,
):
    if path_id:
        ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
        if not ap:
            return []
        check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.AttackPathNode).filter(
            models.AttackPathNode.path_id == path_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
    elif pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.AttackPathNode).filter(
            models.AttackPathNode.pid == pid,
            models.AttackPathNode.deleted_at.is_(None),
        )
    else:
        return []
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.all()


@router.post("/api/attack-path-nodes", response_model=sch.AttackPathNode)
def create_node(
    body: sch.AttackPathNodeCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    require_attack_path_in_project(db, body.path_id, body.pid)
    node = models.AttackPathNode(
        **body.model_dump(),
        id=new_id("apn"),
        created_by=getattr(request.state, "uid", None),
        ts=ts_now(),
    )
    db.add(node)
    log_event(
        db,
        body.pid,
        getattr(request.state, "username", None),
        "attack_path_node",
        "create",
        f"Node created: {node.label}",
    )
    db.commit()
    db.refresh(node)
    bcast(
        body.pid, "attack_path_node", "create", sch.AttackPathNode.model_validate(node).model_dump()
    )
    return node


@router.patch("/api/attack-path-nodes/{node_id}", response_model=sch.AttackPathNode)
def update_node(
    node_id: str,
    body: sch.AttackPathNodeUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    node = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.id == node_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
        .first()
    )
    if not node:
        raise HTTPException(404)
    check_object_access(db, node.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(node, k, v)
    db.commit()
    db.refresh(node)
    bcast(
        node.pid, "attack_path_node", "update", sch.AttackPathNode.model_validate(node).model_dump()
    )
    return node


@router.delete("/api/attack-path-nodes/{node_id}")
def delete_node(
    node_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    node = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.id == node_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
        .first()
    )
    if not node:
        raise HTTPException(404)
    check_object_access(db, node.pid, user, PERM_ATTACK_PATHS_UPDATE)
    node.deleted_at = ts_now()
    log_event(
        db,
        node.pid,
        getattr(request.state, "username", None),
        "attack_path_node",
        "delete",
        f"Node deleted: {node.label}",
    )
    db.commit()
    bcast(node.pid, "attack_path_node", "delete", {"id": node_id})
    return {"ok": True}


# ── Edges ──────────────────────────────────────────────────────────────


@router.get("/api/attack-path-edges", response_model=list[sch.AttackPathEdge])
def list_edges(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    path_id: str | None = None,
):
    if not path_id:
        return []
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not ap:
        return []
    check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_READ)
    q = db.query(models.AttackPathEdge).filter(
        models.AttackPathEdge.path_id == path_id,
        models.AttackPathEdge.deleted_at.is_(None),
    )
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.all()


@router.post("/api/attack-path-edges", response_model=sch.AttackPathEdge)
def create_edge(
    body: sch.AttackPathEdgeCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if body.from_node == body.to_node:
        raise HTTPException(400, "Self-loop edges are not allowed")
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    require_attack_path_in_project(db, body.path_id, body.pid)
    from_node_obj = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.id == body.from_node,
            models.AttackPathNode.path_id == body.path_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
        .first()
    )
    to_node_obj = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.id == body.to_node,
            models.AttackPathNode.path_id == body.path_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
        .first()
    )
    if not from_node_obj:
        raise HTTPException(400, f"from_node '{body.from_node}' not found in this path")
    if not to_node_obj:
        raise HTTPException(400, f"to_node '{body.to_node}' not found in this path")
    edge = models.AttackPathEdge(
        **body.model_dump(),
        id=new_id("ape"),
        created_by=getattr(request.state, "uid", None),
        ts=ts_now(),
    )
    db.add(edge)
    log_event(
        db,
        body.pid,
        getattr(request.state, "username", None),
        "attack_path_edge",
        "create",
        "Edge created",
    )
    db.commit()
    db.refresh(edge)
    bcast(
        body.pid, "attack_path_edge", "create", sch.AttackPathEdge.model_validate(edge).model_dump()
    )
    return edge


@router.patch("/api/attack-path-edges/{edge_id}", response_model=sch.AttackPathEdge)
def update_edge(
    edge_id: str,
    body: sch.AttackPathEdgeUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    edge = (
        db.query(models.AttackPathEdge)
        .filter(
            models.AttackPathEdge.id == edge_id,
            models.AttackPathEdge.deleted_at.is_(None),
        )
        .first()
    )
    if not edge:
        raise HTTPException(404)
    check_object_access(db, edge.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(edge, k, v)
    db.commit()
    db.refresh(edge)
    bcast(
        edge.pid, "attack_path_edge", "update", sch.AttackPathEdge.model_validate(edge).model_dump()
    )
    return edge


@router.delete("/api/attack-path-edges/{edge_id}")
def delete_edge(
    edge_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    edge = (
        db.query(models.AttackPathEdge)
        .filter(
            models.AttackPathEdge.id == edge_id,
            models.AttackPathEdge.deleted_at.is_(None),
        )
        .first()
    )
    if not edge:
        raise HTTPException(404)
    check_object_access(db, edge.pid, user, PERM_ATTACK_PATHS_UPDATE)
    pid = edge.pid
    edge.deleted_at = ts_now()
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "attack_path_edge",
        "delete",
        "Edge deleted",
    )
    db.commit()
    bcast(pid, "attack_path_edge", "delete", {"id": edge_id})
    return {"ok": True}


# ── Branches ───────────────────────────────────────────────────────────


@router.get("/api/attack-path-branches", response_model=list[sch.AttackPathBranch])
def list_branches(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    path_id: str | None = None,
):
    if not path_id:
        return []
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not ap:
        return []
    check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_READ)
    q = db.query(models.AttackPathBranch).filter(
        models.AttackPathBranch.path_id == path_id,
        models.AttackPathBranch.deleted_at.is_(None),
    )
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.all()


@router.post("/api/attack-path-branches", response_model=sch.AttackPathBranch)
def create_branch(
    body: sch.AttackPathBranchCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    require_attack_path_in_project(db, body.path_id, body.pid)
    branch = models.AttackPathBranch(
        **body.model_dump(),
        id=new_id("apb"),
        created_by=getattr(request.state, "uid", None),
        ts=ts_now(),
    )
    db.add(branch)
    log_event(
        db,
        body.pid,
        getattr(request.state, "username", None),
        "attack_path_branch",
        "create",
        f"Branch created: {branch.name}",
    )
    db.commit()
    db.refresh(branch)
    bcast(
        body.pid,
        "attack_path_branch",
        "create",
        sch.AttackPathBranch.model_validate(branch).model_dump(),
    )
    return branch


@router.patch("/api/attack-path-branches/{branch_id}", response_model=sch.AttackPathBranch)
def update_branch(
    branch_id: str,
    body: sch.AttackPathBranchUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    branch = (
        db.query(models.AttackPathBranch)
        .filter(
            models.AttackPathBranch.id == branch_id,
            models.AttackPathBranch.deleted_at.is_(None),
        )
        .first()
    )
    if not branch:
        raise HTTPException(404)
    check_object_access(db, branch.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(branch, k, v)
    db.commit()
    db.refresh(branch)
    bcast(
        branch.pid,
        "attack_path_branch",
        "update",
        sch.AttackPathBranch.model_validate(branch).model_dump(),
    )
    return branch


@router.delete("/api/attack-path-branches/{branch_id}")
def delete_branch(
    branch_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    branch = (
        db.query(models.AttackPathBranch)
        .filter(
            models.AttackPathBranch.id == branch_id,
            models.AttackPathBranch.deleted_at.is_(None),
        )
        .first()
    )
    if not branch:
        raise HTTPException(404)
    check_object_access(db, branch.pid, user, PERM_ATTACK_PATHS_UPDATE)
    branch.deleted_at = ts_now()
    log_event(
        db,
        branch.pid,
        getattr(request.state, "username", None),
        "attack_path_branch",
        "delete",
        f"Branch deleted: {branch.name}",
    )
    db.commit()
    bcast(branch.pid, "attack_path_branch", "delete", {"id": branch_id})
    return {"ok": True}


# ── Entity Links ───────────────────────────────────────────────────────


@router.get("/api/entity-links", response_model=list[sch.EntityLink])
def list_entity_links(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    direction: str = "forward",
):
    if not pid:
        return []
    check_pid_access(db, pid, user, PERM_LINKS_READ)
    q = db.query(models.EntityLink).filter(
        models.EntityLink.pid == pid,
        models.EntityLink.deleted_at.is_(None),
    )
    if entity_type and entity_id:
        if direction == "back":
            q = q.filter(
                models.EntityLink.dst_type == entity_type,
                models.EntityLink.dst_id == entity_id,
            )
        else:
            q = q.filter(
                models.EntityLink.src_type == entity_type,
                models.EntityLink.src_id == entity_id,
            )
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.all()


@router.post("/api/entity-links", response_model=sch.EntityLink)
def create_entity_link(
    body: sch.EntityLinkCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_LINKS_MANAGE)
    existing = (
        db.query(models.EntityLink)
        .filter(
            models.EntityLink.pid == body.pid,
            models.EntityLink.src_type == body.src_type,
            models.EntityLink.src_id == body.src_id,
            models.EntityLink.dst_type == body.dst_type,
            models.EntityLink.dst_id == body.dst_id,
            models.EntityLink.link_type == body.link_type,
            models.EntityLink.deleted_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(409, "Duplicate link")
    link = models.EntityLink(
        **body.model_dump(),
        id=new_id("el"),
        created_by=getattr(request.state, "uid", None),
        ts=ts_now(),
    )
    db.add(link)
    log_event(
        db,
        body.pid,
        getattr(request.state, "username", None),
        "entity_link",
        "create",
        f"Link created: {body.src_type}/{body.src_id} → {body.dst_type}/{body.dst_id}",
    )
    db.commit()
    db.refresh(link)
    bcast(body.pid, "entity_link", "create", sch.EntityLink.model_validate(link).model_dump())
    return link


@router.delete("/api/entity-links/{link_id}")
def delete_entity_link(
    link_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    link = (
        db.query(models.EntityLink)
        .filter(
            models.EntityLink.id == link_id,
            models.EntityLink.deleted_at.is_(None),
        )
        .first()
    )
    if not link:
        raise HTTPException(404)
    check_pid_access(db, link.pid, user, PERM_LINKS_MANAGE)
    link.deleted_at = ts_now()
    log_event(
        db,
        link.pid,
        getattr(request.state, "username", None),
        "entity_link",
        "delete",
        f"Link deleted: {link.src_type}/{link.src_id} → {link.dst_type}/{link.dst_id}",
    )
    db.commit()
    bcast(link.pid, "entity_link", "delete", {"id": link_id})
    return {"ok": True}


# ── Risk recalculation ─────────────────────────────────────────────────


@router.post("/api/attack-paths/{path_id}/recalculate-risk")
def recalculate_risk(
    path_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    path = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(404)
    check_object_access(db, path.pid, user, PERM_ATTACK_PATHS_UPDATE)
    nodes = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.path_id == path_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
        .all()
    )
    branches = (
        db.query(models.AttackPathBranch)
        .filter(
            models.AttackPathBranch.path_id == path_id,
            models.AttackPathBranch.deleted_at.is_(None),
        )
        .all()
    )
    result = calculate_path_risk(path, nodes, branches)
    path.risk_score = result["risk_score"]
    path.likelihood_score = result["likelihood_score"]
    path.impact_score = result["impact_score"]
    db.commit()
    bcast(path.pid, "attack_path", "risk_recalculated", {"id": path_id, **result})
    return result


# ── Versioning ──────────────────────────────────────────────────────────


def _serialize_snapshot(db, path_id):
    nodes = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.path_id == path_id,
            models.AttackPathNode.deleted_at.is_(None),
        )
        .all()
    )
    edges = (
        db.query(models.AttackPathEdge)
        .filter(
            models.AttackPathEdge.path_id == path_id,
            models.AttackPathEdge.deleted_at.is_(None),
        )
        .all()
    )
    branches = (
        db.query(models.AttackPathBranch)
        .filter(
            models.AttackPathBranch.path_id == path_id,
            models.AttackPathBranch.deleted_at.is_(None),
        )
        .all()
    )
    return {
        "nodes": [sch.AttackPathNode.model_validate(n).model_dump() for n in nodes],
        "edges": [sch.AttackPathEdge.model_validate(e).model_dump() for e in edges],
        "branches": [sch.AttackPathBranch.model_validate(b).model_dump() for b in branches],
    }


@router.get("/api/attack-paths/{path_id}/versions", response_model=list[sch.AttackPathVersionRead])
def list_versions(
    path_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    path = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(404)
    check_object_access(db, path.pid, user, PERM_ATTACK_PATHS_READ)
    return (
        db.query(models.AttackPathVersion)
        .filter(
            models.AttackPathVersion.path_id == path_id,
        )
        .order_by(models.AttackPathVersion.version.desc())
        .all()
    )


@router.post("/api/attack-paths/{path_id}/snapshot", response_model=sch.AttackPathVersionRead)
def create_snapshot(
    path_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    path = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(404)
    check_object_access(db, path.pid, user, PERM_ATTACK_PATHS_UPDATE)
    snapshot = _serialize_snapshot(db, path_id)
    path.version = (path.version or 0) + 1

    prev = (
        db.query(models.AttackPathVersion)
        .filter(models.AttackPathVersion.path_id == path_id)
        .order_by(models.AttackPathVersion.version.desc())
        .first()
    )

    if prev and prev.snapshot:
        prev_nodes = {n["id"]: n for n in prev.snapshot.get("nodes", [])}
        new_nodes = {n["id"]: n for n in snapshot.get("nodes", [])}
        added = len(set(new_nodes) - set(prev_nodes))
        removed = len(set(prev_nodes) - set(new_nodes))
        common = set(prev_nodes) & set(new_nodes)
        changed = sum(
            1
            for nid in common
            if prev_nodes[nid].get("label") != new_nodes[nid].get("label")
            or prev_nodes[nid].get("node_status") != new_nodes[nid].get("node_status")
        )
        summary_parts = []
        if added:
            summary_parts.append(f"+{added} nodes")
        if removed:
            summary_parts.append(f"-{removed} nodes")
        if changed:
            summary_parts.append(f"~{changed} changed")
        change_summary = ", ".join(summary_parts) if summary_parts else "No changes"
    else:
        node_count = len(snapshot.get("nodes", []))
        edge_count = len(snapshot.get("edges", []))
        change_summary = f"Initial snapshot: {node_count} nodes, {edge_count} edges"

    ver = models.AttackPathVersion(
        id=new_id("apv"),
        path_id=path_id,
        version=path.version,
        snapshot=snapshot,
        change_summary=change_summary,
        created_by=getattr(request.state, "uid", None),
        ts=ts_now(),
    )
    db.add(ver)
    db.commit()
    db.refresh(ver)
    bcast(path.pid, "attack_path_version", "create", {"path_id": path_id, "version": ver.version})
    return ver


@router.post("/api/attack-paths/{path_id}/revert/{version}")
def revert_version(
    path_id: str,
    version: int,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    path = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not path:
        raise HTTPException(404)
    check_object_access(db, path.pid, user, PERM_ATTACK_PATHS_UPDATE)
    ver = (
        db.query(models.AttackPathVersion)
        .filter(
            models.AttackPathVersion.path_id == path_id,
            models.AttackPathVersion.version == version,
        )
        .first()
    )
    if not ver or not ver.snapshot:
        raise HTTPException(404, "Version not found")
    current_snapshot = _serialize_snapshot(db, path_id)
    backup = models.AttackPathVersion(
        id=new_id("apv"),
        path_id=path_id,
        version=path.version or 0,
        snapshot=current_snapshot,
        change_summary=f"Auto-backup before revert to v{version}",
        created_by=getattr(request.state, "uid", None),
        ts=ts_now(),
    )
    db.add(backup)
    for e in db.query(models.AttackPathEdge).filter(models.AttackPathEdge.path_id == path_id).all():
        e.deleted_at = ts_now()
    for n in db.query(models.AttackPathNode).filter(models.AttackPathNode.path_id == path_id).all():
        n.deleted_at = ts_now()
    for b in (
        db.query(models.AttackPathBranch).filter(models.AttackPathBranch.path_id == path_id).all()
    ):
        b.deleted_at = ts_now()
    snap = ver.snapshot if isinstance(ver.snapshot, dict) else {}
    id_map = {}
    for nd in snap.get("nodes", []):
        old_id = nd.get("id", "")
        new_node_id = new_id("apn")
        id_map[old_id] = new_node_id
        existing = (
            db.query(models.AttackPathNode)
            .filter(
                models.AttackPathNode.path_id == path_id,
                models.AttackPathNode.label == nd.get("label", ""),
                models.AttackPathNode.ts == nd.get("ts", ""),
                models.AttackPathNode.deleted_at.is_(None),
            )
            .first()
        )
        if not existing:
            db.add(
                models.AttackPathNode(
                    id=new_node_id,
                    path_id=path_id,
                    pid=nd.get("pid", path.pid),
                    kind=nd.get("kind", "step"),
                    label=nd.get("label", ""),
                    sublabel=nd.get("sublabel", ""),
                    technique=nd.get("technique", ""),
                    mitre_id=nd.get("mitre_id", ""),
                    notes=nd.get("notes", ""),
                    node_status=nd.get("node_status", "hypothetical"),
                    confidence=nd.get("confidence", "0.5"),
                    ref_type=nd.get("ref_type"),
                    ref_id=nd.get("ref_id"),
                    position=nd.get("position", {}),
                    host_id=nd.get("host_id"),
                    created_by=nd.get("created_by"),
                    ts=nd.get("ts", ts_now()),
                )
            )
    for ed in snap.get("edges", []):
        from_node = id_map.get(ed.get("from_node", ""), ed.get("from_node", ""))
        to_node = id_map.get(ed.get("to_node", ""), ed.get("to_node", ""))
        db.add(
            models.AttackPathEdge(
                id=new_id("ape"),
                path_id=path_id,
                pid=ed.get("pid", path.pid),
                from_node=from_node,
                to_node=to_node,
                edge_type=ed.get("edge_type", "leads_to"),
                branch_id=ed.get("branch_id"),
                condition=ed.get("condition", ""),
                edge_status=ed.get("edge_status", "hypothetical"),
                weight=ed.get("weight", 0),
                technique=ed.get("technique", ""),
                mitre_id=ed.get("mitre_id", ""),
                created_by=ed.get("created_by"),
                ts=ed.get("ts", ts_now()),
            )
        )
    for bd in snap.get("branches", []):
        db.add(
            models.AttackPathBranch(
                id=new_id("apb"),
                path_id=path_id,
                pid=bd.get("pid", path.pid),
                name=bd.get("name", ""),
                root_node=bd.get("root_node"),
                status=bd.get("status", "hypothetical"),
                owner_user_id=bd.get("owner_user_id"),
                probability=bd.get("probability", "0.5"),
                complexity=bd.get("complexity", "medium"),
                risk_score=bd.get("risk_score"),
                parent_branch_id=bd.get("parent_branch_id"),
                description=bd.get("description", ""),
                created_by=bd.get("created_by"),
                ts=bd.get("ts", ts_now()),
            )
        )
    path.version = (path.version or 0) + 1
    db.commit()
    bcast(path.pid, "attack_path_version", "revert", {"path_id": path_id, "reverted_to": version})
    return {"ok": True, "version": path.version}


# ── Dependency graph (L-2) ─────────────────────────────────────────────


@router.get("/api/entity-links/dependency-graph")
def dependency_graph(
    pid: str,
    root_type: str,
    root_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_LINKS_READ)
    try:
        result = db.execute(
            text("""
            WITH RECURSIVE dep AS (
                SELECT id, src_type, src_id, dst_type, dst_id, link_type, 0 as depth
                FROM entity_links
                WHERE pid = :pid AND src_type = :rt AND src_id = :ri
                  AND link_type IN ('depends_on','blocks','part_of')
                  AND deleted_at IS NULL
                UNION ALL
                SELECT el.id, el.src_type, el.src_id, el.dst_type, el.dst_id, el.link_type, dep.depth + 1
                FROM entity_links el
                JOIN dep ON el.src_type = dep.dst_type AND el.src_id = dep.dst_id
                WHERE el.pid = :pid AND el.link_type IN ('depends_on','blocks','part_of')
                  AND el.deleted_at IS NULL AND dep.depth < 10
            )
            SELECT * FROM dep ORDER BY depth
        """),
            {"pid": pid, "rt": root_type, "ri": root_id},
        )
        rows = [
            {
                "id": r[0],
                "src_type": r[1],
                "src_id": r[2],
                "dst_type": r[3],
                "dst_id": r[4],
                "link_type": r[5],
                "depth": r[6],
            }
            for r in result
        ]
    except Exception:
        rows = []
        visited = set()
        queue = [(root_type, root_id, 0)]
        while queue:
            st, si, depth = queue.pop(0)
            key = f"{st}:{si}"
            if key in visited or depth >= 10:
                continue
            visited.add(key)
            links = (
                db.query(models.EntityLink)
                .filter(
                    models.EntityLink.pid == pid,
                    models.EntityLink.src_type == st,
                    models.EntityLink.src_id == si,
                    models.EntityLink.link_type.in_(["depends_on", "blocks", "part_of"]),
                    models.EntityLink.deleted_at.is_(None),
                )
                .all()
            )
            for link in links:
                rows.append(
                    {
                        "id": link.id,
                        "src_type": link.src_type,
                        "src_id": link.src_id,
                        "dst_type": link.dst_type,
                        "dst_id": link.dst_id,
                        "link_type": link.link_type,
                        "depth": depth,
                    }
                )
                queue.append((link.dst_type, link.dst_id, depth + 1))
    return rows
