"""
Inference rules over the canonical graph (GRAPH_MODEL_REFACTOR Step 4).

Each rule is a small, named, independently-testable function that reads the
canonical nodes and emits *additional* canonical nodes/edges carrying
provenance (``source`` = "rule:<name>", ``confidence``, ``reason``). This is
where the heuristics currently buried in the ~1.8k-line ``topology/_smart_build.py``
move to, one rule at a time — so a new inference is a small registered
function, not an edit to a monolith.

Rules are additive and opt-in: ``project_graph`` returns the plain projection
by default; ``apply_rules`` layers inference on top only when asked.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable

from .graph_model import Edge, Node, uid

# name -> rule(nodes: list[dict], ctx: dict | None) -> (list[Node], list[Edge])
RULES: dict[str, Callable[..., tuple[list[Node], list[Edge]]]] = {}


def rule(name: str):
    def register(fn):
        RULES[name] = fn
        fn.rule_name = name
        return fn

    return register


def _host_ipv4s(node: dict):
    """Yield parsed IPv4 addresses for a host node (its `ip` plus any `ips`)."""
    attrs = node.get("attrs") or {}
    candidates = [attrs.get("ip")] + list(attrs.get("ips") or [])
    for raw in candidates:
        if not raw:
            continue
        try:
            yield ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue


def _parse_scope_subnets(ctx: dict | None):
    """Parse the ground-truth CIDRs from a rule context (see
    ``graph_model.subnet_context``) into ``[(ip_network, meta), ...]``."""
    out = []
    for s in ((ctx or {}).get("subnets") or []):
        try:
            net = ipaddress.ip_network(s["cidr"], strict=False)
        except (ValueError, KeyError):
            continue
        out.append((net, s))
    return out


def _match_scope(ip, scope_nets):
    """Most-specific declared subnet containing ``ip``, or None."""
    best = None
    for net, meta in scope_nets:
        if ip.version == net.version and ip in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, meta)
    return best


@rule("same_subnet")
def same_subnet(nodes: list[dict], ctx: dict | None = None) -> tuple[list[Node], list[Edge]]:
    """Group hosts into a canonical `subnet` node they connect to via
    `member_of`. Uses the stdlib `ipaddress` module and real network arithmetic
    — a correct replacement for the legacy string-split ``_infer._get_subnet``
    (hardcoded /24, IP split on '.', silent 8-host cap). A subnet node instead
    of O(n^2) host<->host edges keeps the graph readable at scale and makes the
    subnet addressable.

    When ``ctx`` carries the engagement's declared CIDRs
    (``graph_model.subnet_context``), a host is placed into the real subnet it
    falls in (e.g. a /23 or /16) with higher confidence; otherwise it falls
    back to assuming a /24 (IPv4) or /64 (IPv6).
    """
    scope_nets = _parse_scope_subnets(ctx)
    nodes_out: list[Node] = []
    edges_out: list[Edge] = []
    seen_subnets: set[str] = set()

    for n in nodes:
        if n.get("type") != "host":
            continue
        subnets_for_host: set[str] = set()
        for ip in _host_ipv4s(n):
            match = _match_scope(ip, scope_nets)
            if match is not None:
                net, meta = match
                cidr = str(net)
                confidence = 0.95
                reason = f"IP in declared scope {cidr}"
                attrs = {"cidr": cidr, "version": ip.version, "scope": True,
                         "in_scope": meta.get("in_scope", True)}
            else:
                prefix = 24 if ip.version == 4 else 64
                net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                cidr = str(net)
                confidence = 0.9
                reason = f"IP in {cidr} (assumed /{prefix})"
                attrs = {"cidr": cidr, "version": ip.version, "scope": False}
            if cidr in subnets_for_host:
                continue
            subnets_for_host.add(cidr)
            if cidr not in seen_subnets:
                seen_subnets.add(cidr)
                nodes_out.append(
                    Node(type="subnet", id=cidr, pid=n["pid"], label=cidr,
                         source="rule:same_subnet", attrs=attrs)
                )
            edges_out.append(
                Edge(n["uid"], uid("subnet", cidr), type="member_of",
                     source="rule:same_subnet", confidence=confidence, reason=reason)
            )
    return nodes_out, edges_out


_GW_ROLES = {"router", "firewall", "network_device", "gateway"}
_GW_TAGS = {"router", "firewall", "fw", "gateway", "pivot", "border"}
_GW_OS = ("cisco", "juniper", "pfsense", "opnsense", "fortinet", "vyos",
          "checkpoint", "mikrotik", "router", "fortigate")
_GW_IP_HOSTPARTS = {1, 2, 254, 253, 252}


def _gateway_signal(attrs: dict, ip) -> tuple[bool, float, str]:
    """Return (is_gateway, confidence, reason). Explicit role/tag/OS signals
    are strong; a bare gateway-ish host part (.1/.254/...) is weak."""
    if (attrs.get("role") or "").lower() in _GW_ROLES:
        return True, 0.9, f"role={attrs.get('role')}"
    tags = {str(t).lower() for t in (attrs.get("tags") or [])}
    if tags & _GW_TAGS:
        return True, 0.9, f"tag={','.join(sorted(tags & _GW_TAGS))}"
    os_l = (attrs.get("os") or "").lower()
    if any(kw in os_l for kw in _GW_OS):
        return True, 0.85, f"os={os_l[:20]}"
    if ip is not None and ip.version == 4 and (int(ip) & 0xFF) in _GW_IP_HOSTPARTS:
        return True, 0.5, f"host part .{int(ip) & 0xFF}"
    return False, 0.0, ""


@rule("same_domain")
def same_domain(nodes: list[dict], ctx: dict | None = None) -> tuple[list[Node], list[Edge]]:
    """Group hosts that share a Windows/AD domain into a canonical `domain`
    node (`host --member_of_domain--> domain`). AD context is high-value for
    red teams; the domain is a stored host attribute, so confidence is 1.0."""
    nodes_out: list[Node] = []
    edges_out: list[Edge] = []
    seen: set[str] = set()
    for n in nodes:
        if n.get("type") != "host":
            continue
        dom = str((n.get("attrs") or {}).get("domain") or "").strip().lower()
        if not dom:
            continue
        if dom not in seen:
            seen.add(dom)
            nodes_out.append(Node(type="domain", id=dom, pid=n["pid"], label=dom,
                                  source="rule:same_domain", attrs={"domain": dom}))
        edges_out.append(Edge(n["uid"], uid("domain", dom), type="member_of_domain",
                              source="rule:same_domain", confidence=1.0,
                              reason=f"host.domain={dom}"))
    return nodes_out, edges_out


@rule("gateway")
def gateway(nodes: list[dict], ctx: dict | None = None) -> tuple[list[Node], list[Edge]]:
    """Mark hosts that look like a subnet gateway and connect them to the
    subnet they route (`host --gateway_of--> subnet`). Pairs with same_subnet
    (the subnet node must exist for the edge to survive apply_rules).

    When ``ctx`` declares a subnet's real gateway IP, a host holding that IP is
    marked its gateway with confidence 1.0 (ground truth). Otherwise it falls
    back to the heuristic signals (role/tag/OS, or a gateway-ish host part) and
    attaches to the declared subnet the IP falls in, else an assumed /24."""
    scope_nets = _parse_scope_subnets(ctx)
    gw_by_ip = {meta["gateway_ip"]: (net, meta) for net, meta in scope_nets if meta.get("gateway_ip")}
    edges_out: list[Edge] = []
    for n in nodes:
        if n.get("type") != "host":
            continue
        attrs = n.get("attrs") or {}
        ip = next(_host_ipv4s(n), None)
        if ip is None:
            continue
        # Ground truth: the host's IP is a declared scope gateway.
        if str(ip) in gw_by_ip:
            net, _meta = gw_by_ip[str(ip)]
            edges_out.append(Edge(n["uid"], uid("subnet", str(net)), type="gateway_of",
                                  source="rule:gateway", confidence=1.0,
                                  reason="declared scope gateway"))
            continue
        is_gw, conf, reason = _gateway_signal(attrs, ip)
        if not is_gw:
            continue
        match = _match_scope(ip, scope_nets)
        if match is not None:
            cidr = str(match[0])
        else:
            prefix = 24 if ip.version == 4 else 64
            cidr = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        edges_out.append(Edge(n["uid"], uid("subnet", cidr), type="gateway_of",
                              source="rule:gateway", confidence=conf, reason=reason))
    return [], edges_out


def _host_ip_strings(node: dict):
    """Canonical string form of every IP on a host node (dedup-friendly)."""
    return {str(ip) for ip in _host_ipv4s(node)}


def _host_identity(node: dict) -> tuple[str, str]:
    """Return (short_hostname, domain) for a host, normalised for matching.

    Handles the cross-tool split where one source stores an FQDN
    (``dc01.corp.local``) and another a short name plus a ``domain`` field —
    both must resolve to the same (short, domain) key."""
    attrs = node.get("attrs") or {}
    hn = str(attrs.get("hostname") or "").strip().lower()
    dom = str(attrs.get("domain") or "").strip().lower()
    if "." in hn:
        short, _, rest = hn.partition(".")
        if not dom:
            dom = rest
        hn = short
    return hn, dom


@rule("same_as")
def same_as(nodes: list[dict], ctx: dict | None = None) -> tuple[list[Node], list[Edge]]:
    """Resolve cross-tool identity: link host records that are very likely the
    *same physical machine* but were created as separate rows because different
    tools key on different attributes (e.g. an nmap host keyed on IP with no
    hostname, and a BloodHound host keyed on hostname with no IP). Emits
    symmetric `host --same_as--> host` edges with provenance so the unified
    graph knows two nodes are one entity — the foundation for later merging.

    Signals, strongest first:
      - a shared IP address                → confidence 1.0
      - same short hostname AND domain     → confidence 0.95
      - same short hostname, no domain     → confidence 0.7 (could collide
        across domains, so lower)
    """
    hosts = [n for n in nodes if n.get("type") == "host"]
    edges: list[Edge] = []
    # Best confidence/reason per unordered host pair (a pair may match on
    # several signals — keep the strongest).
    best: dict[tuple[str, str], tuple[float, str]] = {}

    def consider(a: str, b: str, conf: float, reason: str):
        if a == b:
            return
        key = (a, b) if a < b else (b, a)
        if key not in best or conf > best[key][0]:
            best[key] = (conf, reason)

    by_ip: dict[str, list[str]] = defaultdict(list)
    for n in hosts:
        for ip in _host_ip_strings(n):
            by_ip[ip].append(n["uid"])
    for ip, uids in by_ip.items():
        us = sorted(set(uids))
        for i in range(len(us)):
            for j in range(i + 1, len(us)):
                consider(us[i], us[j], 1.0, f"shared IP {ip}")

    by_hd: dict[tuple[str, str], list[str]] = defaultdict(list)
    for n in hosts:
        hn, dom = _host_identity(n)
        if hn:
            by_hd[(hn, dom)].append(n["uid"])
    for (hn, dom), uids in by_hd.items():
        us = sorted(set(uids))
        for i in range(len(us)):
            for j in range(i + 1, len(us)):
                if dom:
                    consider(us[i], us[j], 0.95, f"hostname {hn} in {dom}")
                else:
                    consider(us[i], us[j], 0.7, f"hostname {hn} (no domain)")

    for (a, b), (conf, reason) in best.items():
        edges.append(Edge(a, b, type="same_as", source="rule:same_as",
                          confidence=conf, reason=reason, directed=False))
    return [], edges


@rule("entry_path")
def entry_path(nodes: list[dict], ctx: dict | None = None) -> tuple[list[Node], list[Edge]]:
    """Surface the engagement's declared entry points as graph structure. From
    `Scope` rows flagged ``is_entry`` (with an optional ``via_host_id``), emit a
    `host --entry_to--> subnet` edge — "this subnet is reached through this host"
    — and make the entry subnet visible even if no host has been placed in it
    yet. Ground-truth from the scope, so confidence 1.0.

    Turns operator-declared reachability (which otherwise only lives in the
    scope config) into a first-class relationship every graph consumer can use.
    """
    scope_nets = _parse_scope_subnets(ctx)
    host_uids = {n["uid"] for n in nodes if n.get("type") == "host"}
    pid = nodes[0]["pid"] if nodes else ""
    nodes_out: list[Node] = []
    edges_out: list[Edge] = []
    seen_subnet: set[str] = set()
    for net, meta in scope_nets:
        if not meta.get("is_entry"):
            continue
        cidr = str(net)
        if cidr not in seen_subnet:
            seen_subnet.add(cidr)
            nodes_out.append(
                Node(type="subnet", id=cidr, pid=pid, label=cidr, source="rule:entry_path",
                     attrs={"cidr": cidr, "scope": True, "is_entry": True,
                            "in_scope": meta.get("in_scope", True)})
            )
        via = (meta.get("via_host_id") or "").strip()
        if via and uid("host", via) in host_uids:
            edges_out.append(
                Edge(uid("host", via), uid("subnet", cidr), type="entry_to",
                     source="rule:entry_path", confidence=1.0, reason="declared entry point")
            )
    return nodes_out, edges_out


def apply_rules(graph: dict, names: list[str] | None = None, ctx: dict | None = None) -> dict:
    """Layer inference onto a projected graph (from ``project_graph``). Returns
    a new dict with inferred nodes/edges appended and counts recomputed. Unknown
    rule names are ignored. Nodes already present (by uid) are not duplicated.

    ``ctx`` is an optional ground-truth context (see
    ``graph_model.subnet_context``) passed to every rule — rules that don't use
    it ignore it."""
    selected = list(RULES) if names is None else [n for n in names if n in RULES]
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    present = {n["uid"] for n in nodes}

    for name in selected:
        # Pass the accumulated node list so later rules can build on earlier
        # rules' output (e.g. `gateway` referencing `same_subnet`'s subnets).
        new_nodes, new_edges = RULES[name](nodes, ctx)
        for nn in new_nodes:
            d = nn.to_dict()
            if d["uid"] not in present:
                present.add(d["uid"])
                nodes.append(d)
        for ne in new_edges:
            if ne.src_uid in present and ne.dst_uid in present:
                edges.append(ne.to_dict())

    by_type: dict[str, int] = {}
    for n in nodes:
        by_type[n["type"]] = by_type.get(n["type"], 0) + 1

    out = dict(graph)
    out["nodes"] = nodes
    out["edges"] = edges
    out["counts"] = {
        **graph.get("counts", {}),
        "nodes": len(nodes),
        "edges": len(edges),
        "by_type": by_type,
    }
    out["rules_applied"] = selected
    return out
