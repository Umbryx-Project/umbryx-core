"""Tests for canonical inference rules (core/graph_rules.py, Step 4)."""
from app.core.graph_rules import RULES, apply_rules, same_subnet


def _host(uid, ip, ips=None, pid="p1"):
    return {"uid": uid, "type": "host", "id": uid.split(":", 1)[1], "pid": pid,
            "label": ip, "attrs": {"ip": ip, "ips": ips or []}, "source": ""}


def test_same_subnet_registered():
    assert RULES["same_subnet"] is same_subnet


def test_same_subnet_groups_by_real_24():
    nodes = [_host("host:a", "10.0.0.5"), _host("host:b", "10.0.0.9"),
             _host("host:c", "192.168.1.10")]
    subnet_nodes, edges = same_subnet(nodes)
    cidrs = {n.id for n in subnet_nodes}
    assert cidrs == {"10.0.0.0/24", "192.168.1.0/24"}
    # a and b share one subnet, c in another -> 3 member_of edges
    assert len(edges) == 3
    assert all(e.type == "member_of" and e.source == "rule:same_subnet" for e in edges)
    a_edge = next(e for e in edges if e.src_uid == "host:a")
    assert a_edge.dst_uid == "subnet:10.0.0.0/24" and 0.0 <= a_edge.confidence <= 1.0


def test_same_subnet_skips_invalid_ip():
    nodes = [_host("host:a", "not-an-ip"), _host("host:b", "")]
    subnet_nodes, edges = same_subnet(nodes)
    assert subnet_nodes == [] and edges == []


def test_same_subnet_uses_secondary_ips():
    nodes = [_host("host:a", "10.0.0.1", ips=["172.16.5.5"])]
    subnet_nodes, _ = same_subnet(nodes)
    assert {n.id for n in subnet_nodes} == {"10.0.0.0/24", "172.16.5.0/24"}


def test_apply_rules_augments_graph_and_counts():
    graph = {
        "pid": "p1",
        "nodes": [_host("host:a", "10.0.0.5"), _host("host:b", "10.0.0.9")],
        "edges": [],
        "counts": {"nodes": 2, "edges": 0, "dangling": 0, "by_type": {"host": 2}},
    }
    out = apply_rules(graph)
    assert out["rules_applied"] == list(RULES)
    assert out["counts"]["by_type"]["subnet"] == 1  # both hosts, one shared /24
    assert out["counts"]["by_type"]["host"] == 2
    assert out["counts"]["edges"] == 2
    # original graph object is not mutated
    assert graph["counts"]["by_type"] == {"host": 2}


def test_same_domain_groups_hosts():
    from app.core.graph_rules import same_domain
    nodes = [
        {"uid": "host:a", "type": "host", "id": "a", "pid": "p1", "attrs": {"domain": "CORP"}},
        {"uid": "host:b", "type": "host", "id": "b", "pid": "p1", "attrs": {"domain": "corp"}},
        {"uid": "host:c", "type": "host", "id": "c", "pid": "p1", "attrs": {"domain": ""}},
    ]
    dnodes, edges = same_domain(nodes)
    assert [n.id for n in dnodes] == ["corp"]  # normalised + deduped
    assert {e.src_uid for e in edges} == {"host:a", "host:b"}
    assert all(e.type == "member_of_domain" for e in edges)


def test_gateway_detects_and_links_to_subnet():
    from app.core.graph_rules import apply_rules
    graph = {
        "pid": "p1",
        "nodes": [
            {"uid": "host:gw", "type": "host", "id": "gw", "pid": "p1",
             "attrs": {"ip": "10.0.0.1", "ips": [], "role": "router", "tags": [], "os": ""}},
            {"uid": "host:srv", "type": "host", "id": "srv", "pid": "p1",
             "attrs": {"ip": "10.0.0.50", "ips": [], "role": "server", "tags": [], "os": "linux"}},
        ],
        "edges": [],
        "counts": {"by_type": {"host": 2}},
    }
    out = apply_rules(graph)  # same_subnet runs first, so subnet:10.0.0.0/24 exists
    gw_edges = [e for e in out["edges"] if e["type"] == "gateway_of"]
    assert len(gw_edges) == 1
    assert gw_edges[0]["src_uid"] == "host:gw"
    assert gw_edges[0]["dst_uid"] == "subnet:10.0.0.0/24"
    assert gw_edges[0]["confidence"] == 0.9


def test_same_subnet_uses_declared_scope_cidr():
    # Two hosts that a naive /24 would split, but a declared /23 unites.
    ctx = {"subnets": [{"cidr": "10.0.0.0/23", "gateway_ip": "10.0.0.1", "in_scope": True}]}
    nodes = [_host("host:a", "10.0.0.5"), _host("host:b", "10.0.1.9")]
    subnet_nodes, edges = same_subnet(nodes, ctx)
    assert {n.id for n in subnet_nodes} == {"10.0.0.0/23"}
    assert len(edges) == 2
    a_edge = next(e for e in edges if e.src_uid == "host:a")
    assert a_edge.dst_uid == "subnet:10.0.0.0/23"
    assert a_edge.confidence == 0.95  # higher confidence than the assumed /24
    assert subnet_nodes[0].attrs.get("scope") is True


def test_same_subnet_falls_back_without_scope():
    # No ctx -> the assumed-/24 behaviour is unchanged.
    nodes = [_host("host:a", "10.0.0.5"), _host("host:b", "10.0.1.9")]
    subnet_nodes, edges = same_subnet(nodes, None)
    assert {n.id for n in subnet_nodes} == {"10.0.0.0/24", "10.0.1.0/24"}
    assert all(e.confidence == 0.9 for e in edges)


def test_gateway_uses_declared_scope_gateway_ip():
    from app.core.graph_rules import apply_rules
    # host:gw has NO heuristic signal (role=server) — only the declared
    # gateway_ip identifies it, and with ground-truth confidence.
    ctx = {"subnets": [{"cidr": "10.0.0.0/24", "gateway_ip": "10.0.0.1", "in_scope": True}]}
    graph = {
        "pid": "p1",
        "nodes": [
            {"uid": "host:gw", "type": "host", "id": "gw", "pid": "p1",
             "attrs": {"ip": "10.0.0.1", "ips": [], "role": "server", "tags": [], "os": "linux"}},
            {"uid": "host:s", "type": "host", "id": "s", "pid": "p1",
             "attrs": {"ip": "10.0.0.9", "ips": [], "role": "server", "tags": [], "os": "linux"}},
        ],
        "edges": [],
        "counts": {"by_type": {"host": 2}},
    }
    out = apply_rules(graph, ctx=ctx)
    gw_edges = [e for e in out["edges"] if e["type"] == "gateway_of"]
    assert len(gw_edges) == 1
    assert gw_edges[0]["src_uid"] == "host:gw"
    assert gw_edges[0]["dst_uid"] == "subnet:10.0.0.0/24"
    assert gw_edges[0]["confidence"] == 1.0


def _hnode(uid, ip="", ips=None, hostname="", domain="", pid="p1"):
    return {"uid": uid, "type": "host", "id": uid.split(":", 1)[1], "pid": pid,
            "attrs": {"ip": ip, "ips": ips or [], "hostname": hostname, "domain": domain}}


def test_same_as_shared_ip():
    from app.core.graph_rules import same_as
    nodes = [_hnode("host:a", ip="10.0.0.5"), _hnode("host:b", ips=["10.0.0.5"])]
    _, edges = same_as(nodes)
    assert len(edges) == 1
    e = edges[0]
    assert e.type == "same_as" and e.confidence == 1.0 and e.directed is False
    assert {e.src_uid, e.dst_uid} == {"host:a", "host:b"}
    assert "shared IP 10.0.0.5" in e.reason


def test_same_as_matches_fqdn_against_short_name_plus_domain():
    # The exact cross-tool split: nmap stores an FQDN, BloodHound a short name
    # + domain field, and no shared IP (BH host has none).
    from app.core.graph_rules import same_as
    nodes = [_hnode("host:nmap", ip="10.0.0.5", hostname="dc01.corp.local"),
             _hnode("host:bh", hostname="DC01", domain="corp.local")]
    _, edges = same_as(nodes)
    assert len(edges) == 1 and edges[0].confidence == 0.95


def test_same_as_hostname_without_domain_is_weaker():
    from app.core.graph_rules import same_as
    nodes = [_hnode("host:a", hostname="web01"), _hnode("host:b", hostname="WEB01")]
    _, edges = same_as(nodes)
    assert len(edges) == 1 and edges[0].confidence == 0.7


def test_same_as_strongest_signal_wins():
    from app.core.graph_rules import same_as
    nodes = [_hnode("host:a", ip="10.0.0.5", hostname="dc01", domain="corp"),
             _hnode("host:b", ip="10.0.0.5", hostname="dc01", domain="corp")]
    _, edges = same_as(nodes)
    assert len(edges) == 1 and edges[0].confidence == 1.0  # shared IP beats name


def test_same_as_distinct_hosts_have_no_edge():
    from app.core.graph_rules import same_as
    nodes = [_hnode("host:a", ip="10.0.0.5", hostname="dc01", domain="corp"),
             _hnode("host:b", ip="10.0.0.9", hostname="ws01", domain="corp")]
    _, edges = same_as(nodes)
    assert edges == []


def test_same_as_registered_and_applied():
    from app.core.graph_rules import RULES, apply_rules
    assert "same_as" in RULES
    graph = {"pid": "p1", "nodes": [_hnode("host:a", ip="10.0.0.5"),
                                    _hnode("host:b", ips=["10.0.0.5"])],
             "edges": [], "counts": {"by_type": {"host": 2}}}
    out = apply_rules(graph)
    assert any(e["type"] == "same_as" for e in out["edges"])


def test_entry_path_emits_edge_and_subnet():
    from app.core.graph_rules import entry_path
    ctx = {"subnets": [{"cidr": "10.0.0.0/24", "is_entry": True,
                        "via_host_id": "h1", "in_scope": True, "gateway_ip": ""}]}
    nodes = [{"uid": "host:h1", "type": "host", "id": "h1", "pid": "p1",
              "attrs": {"ip": "", "ips": []}}]
    nn, ee = entry_path(nodes, ctx)
    assert any(n.type == "subnet" and n.id == "10.0.0.0/24" for n in nn)
    assert len(ee) == 1
    e = ee[0]
    assert e.type == "entry_to" and e.src_uid == "host:h1"
    assert e.dst_uid == "subnet:10.0.0.0/24" and e.confidence == 1.0


def test_entry_path_declared_but_empty_subnet_still_visible():
    from app.core.graph_rules import entry_path
    # via host not in the project -> no edge, but the declared entry subnet
    # should still appear so the operator sees it exists.
    ctx = {"subnets": [{"cidr": "192.168.9.0/24", "is_entry": True, "via_host_id": "ghost"}]}
    nn, ee = entry_path([], ctx)
    assert [n.id for n in nn] == ["192.168.9.0/24"]
    assert ee == []


def test_entry_path_ignores_non_entry_scopes():
    from app.core.graph_rules import entry_path
    ctx = {"subnets": [{"cidr": "10.0.0.0/24", "is_entry": False, "via_host_id": "h1"}]}
    nn, ee = entry_path([{"uid": "host:h1", "type": "host", "id": "h1", "pid": "p1", "attrs": {}}], ctx)
    assert nn == [] and ee == []


def test_entry_path_survives_apply_rules():
    from app.core.graph_rules import apply_rules
    ctx = {"subnets": [{"cidr": "10.0.0.0/24", "is_entry": True, "via_host_id": "h1"}]}
    graph = {"pid": "p1",
             "nodes": [{"uid": "host:h1", "type": "host", "id": "h1", "pid": "p1",
                        "attrs": {"ip": "10.0.0.1", "ips": []}}],
             "edges": [], "counts": {"by_type": {"host": 1}}}
    out = apply_rules(graph, ctx=ctx)
    entry_edges = [e for e in out["edges"] if e["type"] == "entry_to"]
    assert len(entry_edges) == 1 and entry_edges[0]["src_uid"] == "host:h1"
    assert entry_edges[0]["dst_uid"] == "subnet:10.0.0.0/24"
