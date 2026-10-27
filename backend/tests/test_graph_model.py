"""Tests for the canonical graph projection (core/graph_model.py, Step 1 of
docs/modules/GRAPH_MODEL_REFACTOR.md)."""
import uuid

from app import models
from app.core.graph_model import Edge, Node, project_graph, uid


def _mk(db):
    # Unique pid per call: the test DB is shared in-memory and committed rows
    # persist across tests, so a fixed pid would collide on the second test.
    sfx = uuid.uuid4().hex[:8]
    pid = f"p_graph_{sfx}"
    hid1, hid2 = f"h1_{sfx}", f"h2_{sfx}"
    db.add(models.Project(id=pid, name="Graph Test", added="2026-01-01"))
    db.commit()  # ensure the project exists before FK-bearing children
    db.add(models.Host(id=hid1, pid=pid, ip="10.0.0.1", hostname="dc01",
                       ports=["445", "3389", "445"], services=["SMB", "smb", "RDP"]))
    db.add(models.Host(id=hid2, pid=pid, ip="10.0.0.2", hostname="ws01",
                       ports=["445"], services=["smb"]))
    db.add(models.Finding(id=f"f1_{sfx}", pid=pid, host_id=hid1, title="MS17-010", ts="t"))
    db.add(models.Cred(id=f"c1_{sfx}", pid=pid, username="admin", domain="corp",
                       host_ids=[hid1, hid2]))
    db.add(models.Loot(id=f"l1_{sfx}", pid=pid, host_id=hid2, filename="hashes.txt", ts="t"))
    db.add(models.Note(id=f"n1_{sfx}", pid=pid, title="recon notes", ts="t"))
    # explicit edge via EntityLink (both endpoints exist)
    db.add(models.EntityLink(id=f"e1_{sfx}", pid=pid, src_type="host", src_id=hid1,
                             dst_type="host", dst_id=hid2, link_type="trusts", ts="t"))
    # dangling edge (dst host doesn't exist)
    db.add(models.EntityLink(id=f"e2_{sfx}", pid=pid, src_type="host", src_id=hid1,
                             dst_type="host", dst_id="ghost", link_type="relates_to", ts="t"))
    db.commit()
    return pid, hid1, hid2


def test_uid_namespace():
    assert uid("host", "h1") == "host:h1"


def test_nodes_projected_by_type(db):
    pid, h1, h2 = _mk(db)
    g = project_graph(pid, db)
    by = g["counts"]["by_type"]
    # h1 exposes 2 distinct ports (445 dedup, 3389), h2 exposes 1 -> 3 services
    assert by == {"host": 2, "service": 3, "finding": 1, "cred": 1, "loot": 1, "note": 1}
    assert g["counts"]["nodes"] == 9
    labels = {n["uid"]: n["label"] for n in g["nodes"]}
    assert labels[uid("host", h1)] == "dc01"
    assert any(n["label"] == "admin@corp" and n["type"] == "cred" for n in g["nodes"])


def test_services_promoted_to_nodes(db):
    pid, h1, h2 = _mk(db)
    g = project_graph(pid, db)
    svc = {n["uid"]: n for n in g["nodes"] if n["type"] == "service"}
    # one node per (host, port); duplicate port 445 on h1 is deduped
    assert uid("service", f"{h1}:445") in svc
    assert uid("service", f"{h1}:3389") in svc
    assert uid("service", f"{h2}:445") in svc
    # service names normalised + deduped (SMB/smb -> smb)
    assert svc[uid("service", f"{h1}:445")]["attrs"]["services"] == ["rdp", "smb"]
    # host -> service edge with provenance
    edges = {(e["src_uid"], e["dst_uid"], e["type"]) for e in g["edges"]}
    assert (uid("host", h1), uid("service", f"{h1}:445"), "exposes") in edges


def test_fk_edges_emitted_with_provenance(db):
    pid, h1, h2 = _mk(db)
    g = project_graph(pid, db)
    edges = {(e["src_uid"], e["dst_uid"], e["type"]) for e in g["edges"]}
    assert (uid("host", h1), uid("host", h2), "trusts") in edges
    assert any(dst == uid("host", h1) and t == "affects" for _s, dst, t in edges)
    assert any(dst == uid("host", h2) and t == "collected_from" for _s, dst, t in edges)
    assert {uid("host", h1), uid("host", h2)} <= {
        dst for _s, dst, t in edges if t == "valid_on"
    }
    for e in g["edges"]:
        assert e["source"] and 0.0 <= e["confidence"] <= 1.0


def test_dangling_edges_dropped_and_counted(db):
    pid, h1, h2 = _mk(db)
    g = project_graph(pid, db)
    assert g["counts"]["dangling"] == 1
    assert all(e["dst_uid"] != "host:ghost" for e in g["edges"])
    g2 = project_graph(pid, db, drop_dangling=False)
    assert any(e["dst_uid"] == "host:ghost" for e in g2["edges"])


def test_edge_to_dict_shape():
    e = Edge("host:a", "host:b", type="pivots_to", source="pivot", reason="ssh")
    d = e.to_dict()
    assert d["src_uid"] == "host:a" and d["type"] == "pivots_to" and d["directed"] is True


def test_empty_project(db):
    g = project_graph("p_nonexistent", db)
    assert g["counts"]["nodes"] == 0 and g["edges"] == []


def test_subnet_context_reads_scope_cidrs(db):
    import uuid
    from app.core.graph_model import subnet_context
    sfx = uuid.uuid4().hex[:8]
    pid = f"p_scope_{sfx}"
    db.add(models.Project(id=pid, name="Scope Test", added="2026-01-01"))
    db.commit()
    db.add(models.Scope(id=f"s1_{sfx}", pid=pid, value="10.0.0.0/23",
                        scope_type="cidr", in_scope=True, gateway_ip="10.0.0.1"))
    db.add(models.Scope(id=f"s2_{sfx}", pid=pid, value="corp.local",
                        scope_type="domain"))  # non-cidr, must be ignored
    db.add(models.Scope(id=f"s3_{sfx}", pid=pid, value="not-a-cidr",
                        scope_type="cidr"))  # malformed, must be skipped
    db.commit()
    ctx = subnet_context(db, pid)
    cidrs = {s["cidr"] for s in ctx["subnets"]}
    assert cidrs == {"10.0.0.0/23"}
    entry = next(s for s in ctx["subnets"] if s["cidr"] == "10.0.0.0/23")
    assert entry["gateway_ip"] == "10.0.0.1" and entry["in_scope"] is True
