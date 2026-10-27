"""
Canonical graph model (Step 1 of docs/modules/GRAPH_MODEL_REFACTOR.md).

One node/edge vocabulary that every entity projects into, so graph consumers
work in terms of Node/Edge and never need to know the backing table. This is
an ADDITIVE read layer — it changes no schema and no existing endpoint. Later
steps route the topology/attack-path reads through it and move inference rules
onto it.

A node's identity is ``uid = f"{type}:{id}"`` — one namespace across hosts,
creds, findings, loot, notes and (later) services and module objects.

Edges carry provenance so the graph stays explainable (the property the
existing inference already has and we must not regress):
  - ``source``      where the edge came from ("fk", "entity_link", a rule name)
  - ``confidence``  0..1
  - ``reason``      short human-readable justification
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from .. import models


def uid(node_type: str, node_id: str) -> str:
    return f"{node_type}:{node_id}"


@dataclass
class Node:
    type: str
    id: str
    pid: str
    label: str = ""
    attrs: dict = field(default_factory=dict)
    source: str = ""

    @property
    def uid(self) -> str:
        return uid(self.type, self.id)

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "type": self.type,
            "id": self.id,
            "pid": self.pid,
            "label": self.label,
            "attrs": self.attrs,
            "source": self.source,
        }


@dataclass
class Edge:
    src_uid: str
    dst_uid: str
    type: str = "relates_to"
    confidence: float = 1.0
    source: str = ""
    reason: str = ""
    directed: bool = True

    def to_dict(self) -> dict:
        return {
            "src_uid": self.src_uid,
            "dst_uid": self.dst_uid,
            "type": self.type,
            "confidence": self.confidence,
            "source": self.source,
            "reason": self.reason,
            "directed": self.directed,
        }


def _not_deleted(query, model):
    """Filter soft-deleted rows when the model has a deleted_at column."""
    if hasattr(model, "deleted_at"):
        return query.filter(model.deleted_at.is_(None))
    return query


def _host_nodes(db: Session, pid: str) -> list[Node]:
    out = []
    for h in _not_deleted(db.query(models.Host).filter(models.Host.pid == pid), models.Host).all():
        out.append(
            Node(
                type="host",
                id=h.id,
                pid=pid,
                label=h.hostname or h.ip or h.id,
                source=h.import_source or "",
                attrs={
                    "ip": h.ip,
                    "ips": list(h.ips or []),
                    "hostname": h.hostname,
                    "os": h.os,
                    "status": h.status,
                    "role": h.role,
                    "domain": h.domain,
                    "tags": list(h.tags or []),
                    "is_attacker": h.is_attacker,
                },
            )
        )
    return out


def _norm_services(raw) -> list[str]:
    """Dedupe + canonicalise the host's free-form service names (source data
    is case-inconsistent: 'SMB'/'smb', 'HTTPS'/'https')."""
    seen, out = set(), []
    for s in raw or []:
        key = str(s).strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return sorted(out)


def _service_nodes(db: Session, pid: str) -> tuple[list[Node], list[Edge]]:
    """Promote each host's ports to addressable service nodes
    (GRAPH_MODEL_REFACTOR Step 3). Derived from the existing ports/services
    arrays — no schema change yet. The source data pairs ports and service
    names only as two parallel lists with no index correlation, so we model
    one node per (host, port) and carry the host's normalised service-name
    set as an attribute rather than inventing a port->service mapping that
    isn't in the data."""
    nodes, edges = [], []
    q = _not_deleted(db.query(models.Host).filter(models.Host.pid == pid), models.Host)
    for h in q.all():
        svc_names = _norm_services(h.services)
        seen_ports = set()
        for p in h.ports or []:
            port = str(p).strip()
            if not port or port in seen_ports:
                continue
            seen_ports.add(port)
            sid = f"{h.id}:{port}"
            nodes.append(
                Node(type="service", id=sid, pid=pid, label=port,
                     attrs={"host_id": h.id, "port": port, "services": svc_names})
            )
            edges.append(
                Edge(uid("host", h.id), uid("service", sid), type="exposes",
                     source="host.ports", reason="host exposes port")
            )
    return nodes, edges


def _cred_nodes(db: Session, pid: str) -> tuple[list[Node], list[Edge]]:
    nodes, edges = [], []
    q = _not_deleted(db.query(models.Cred).filter(models.Cred.pid == pid), models.Cred)
    for c in q.all():
        label = c.username + (f"@{c.domain}" if c.domain else "")
        nodes.append(
            Node(
                type="cred", id=c.id, pid=pid, label=label or c.id,
                attrs={"username": c.username, "type": c.type, "service": c.service,
                       "domain": c.domain, "cracked": c.cracked, "is_domain": c.is_domain},
            )
        )
        for hid in c.host_ids or []:
            edges.append(
                Edge(uid("cred", c.id), uid("host", hid), type="valid_on",
                     source="fk", reason="cred.host_ids")
            )
    return nodes, edges


def _finding_nodes(db: Session, pid: str) -> tuple[list[Node], list[Edge]]:
    nodes, edges = [], []
    q = _not_deleted(db.query(models.Finding).filter(models.Finding.pid == pid), models.Finding)
    for f in q.all():
        nodes.append(
            Node(type="finding", id=f.id, pid=pid, label=f.title or f.id, source=f.source or "",
                 attrs={"severity": f.severity, "status": f.status, "cve": f.cve, "cvss": f.cvss})
        )
        if f.host_id:
            edges.append(
                Edge(uid("finding", f.id), uid("host", f.host_id), type="affects",
                     source="fk", reason="finding.host_id")
            )
    return nodes, edges


def _loot_nodes(db: Session, pid: str) -> tuple[list[Node], list[Edge]]:
    nodes, edges = [], []
    q = _not_deleted(db.query(models.Loot).filter(models.Loot.pid == pid), models.Loot)
    for lt in q.all():
        nodes.append(
            Node(type="loot", id=lt.id, pid=pid,
                 label=lt.filename or lt.description or lt.loot_type or lt.id,
                 attrs={"loot_type": lt.loot_type, "content_type": lt.content_type,
                        "file_size": lt.file_size})
        )
        if lt.host_id:
            edges.append(
                Edge(uid("loot", lt.id), uid("host", lt.host_id), type="collected_from",
                     source="fk", reason="loot.host_id")
            )
    return nodes, edges


def _note_nodes(db: Session, pid: str) -> tuple[list[Node], list[Edge]]:
    nodes, edges = [], []
    q = _not_deleted(db.query(models.Note).filter(models.Note.pid == pid), models.Note)
    for n in q.all():
        nodes.append(
            Node(type="note", id=n.id, pid=pid, label=n.title or n.id,
                 attrs={"phase": n.phase, "tags": list(n.tags or []), "starred": n.starred})
        )
        if getattr(n, "host_id", None):
            edges.append(
                Edge(uid("note", n.id), uid("host", n.host_id), type="documents",
                     source="fk", reason="note.host_id")
            )
    return nodes, edges


def _pivot_edges(db: Session, pid: str) -> list[Edge]:
    edges = []
    for p in db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid).all():
        if p.source_host_id and p.target_host_id:
            edges.append(
                Edge(uid("host", p.source_host_id), uid("host", p.target_host_id),
                     type="pivots_to", source="pivot",
                     reason=(p.label or p.pivot_type or "pivot"))
            )
    return edges


def _entity_link_edges(db: Session, pid: str) -> list[Edge]:
    edges = []
    q = db.query(models.EntityLink).filter(models.EntityLink.pid == pid)
    q = _not_deleted(q, models.EntityLink)
    for lk in q.all():
        edges.append(
            Edge(uid(lk.src_type, lk.src_id), uid(lk.dst_type, lk.dst_id),
                 type=lk.link_type or "relates_to", source="entity_link",
                 reason=lk.comment or "")
        )
    return edges


def project_graph(pid: str, db: Session, *, drop_dangling: bool = True) -> dict:
    """Project a project's entities into the canonical Node/Edge graph.

    Pure read, no mutation. With ``drop_dangling`` (default), edges whose
    endpoints aren't both present as nodes are omitted from ``edges`` and
    counted under ``dangling`` instead — so consumers get a clean graph while
    still seeing that dangling references exist.
    """
    nodes: list[Node] = []
    edges: list[Edge] = []

    nodes += _host_nodes(db, pid)
    for _gen in (_service_nodes, _cred_nodes, _finding_nodes, _loot_nodes, _note_nodes):
        n, e = _gen(db, pid)
        nodes += n
        edges += e
    edges += _pivot_edges(db, pid)
    edges += _entity_link_edges(db, pid)

    present = {node.uid for node in nodes}
    kept, dangling = [], 0
    for edge in edges:
        if edge.src_uid in present and edge.dst_uid in present:
            kept.append(edge)
        elif drop_dangling:
            dangling += 1
        else:
            kept.append(edge)

    return {
        "pid": pid,
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in kept],
        "counts": {
            "nodes": len(nodes),
            "edges": len(kept),
            "dangling": dangling,
            "by_type": _count_by_type(nodes),
        },
    }


def _count_by_type(nodes: list[Node]) -> dict:
    out: dict[str, int] = {}
    for n in nodes:
        out[n.type] = out.get(n.type, 0) + 1
    return out


def subnet_context(db: Session, pid: str) -> dict:
    """Ground-truth network context for the inference rules, read from the
    engagement's `Scope` entries (the operator-defined CIDRs and gateways).

    The `same_subnet`/`gateway` rules otherwise *assume* a /24 and guess the
    gateway from the host part — accurate only by luck. When the engagement has
    declared its real ranges (e.g. a /23 or /16) and gateway IPs, this lets the
    rules group hosts into the true subnet and mark the real gateway instead.

    Returns ``{"subnets": [{"cidr","gateway_ip","in_scope","is_entry",
    "via_host_id"}, ...]}`` — only well-formed CIDR scope rows are included.
    """
    subnets: list[dict] = []
    rows = (
        db.query(models.Scope)
        .filter(models.Scope.pid == pid, models.Scope.scope_type == "cidr")
        .all()
    )
    import ipaddress

    for s in rows:
        raw = (s.value or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        subnets.append({
            "cidr": str(net),
            "gateway_ip": (s.gateway_ip or "").strip(),
            "in_scope": bool(s.in_scope),
            "is_entry": bool(s.is_entry),
            "via_host_id": (s.via_host_id or "").strip(),
        })
    return {"subnets": subnets}
