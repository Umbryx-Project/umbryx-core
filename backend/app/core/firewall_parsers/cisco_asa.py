"""
Cisco ASA `show running-config` parser.

ASA's config model differs from IOS in three ways this parser has to
handle specifically: interfaces are named logically via `nameif` (carried
into Interface.zone, e.g. "outside"/"inside") rather than referenced by
their physical name alone; ACLs/NAT resolve against `object`/`object-group
network` (ASA's object model — a single address vs. a group, both
resolved inline before AclRule/NatRule are built, same policy as IOS's
object-groups); and local-user secrets here are always a one-way hash
(`password <hash> encrypted`), never a reversible encoding like IOS
type-7 — recoverable_secret is always None.

Parsing is a single-pass, indentation-aware line scanner using only
str.split()/startswith() — no regex, so malformed/adversarial input can't
trigger catastrophic backtracking.
"""

from __future__ import annotations

from .base import FirewallConfigParser, FirewallParserRegistry
from .schema import (
    AclRule,
    ArpEntry,
    DhcpLease,
    Interface,
    LocalUser,
    NatRule,
    ObjectGroup,
    ParsedConfig,
    Route,
    SystemInfo,
    VendorInfo,
)
from .util import (
    extract_ip_and_mac,
    is_public_ip,
    looks_like_ip,
    looks_like_mac,
    normalize_mac,
    scan_operational_table,
)

_DETECT_MARKERS = (
    "ciscoasa",
    ": saved",
    "asa version",
)


def _consume_addr(tokens: list[str], i: int, objs: dict[str, ObjectGroup]) -> tuple[str, int]:
    if i >= len(tokens):
        return "any", i
    tok = tokens[i]
    if tok == "any" or tok == "any4" or tok == "any6":
        return "any", i + 1
    if tok == "host" and i + 1 < len(tokens):
        return tokens[i + 1], i + 2
    if tok == "object" and i + 1 < len(tokens):
        return _resolve_object(tokens[i + 1], objs), i + 2
    if tok == "object-group" and i + 1 < len(tokens):
        return _resolve_object(tokens[i + 1], objs), i + 2
    return tok, i + 1


def _resolve_object(name: str, objs: dict[str, ObjectGroup]) -> str:
    grp = objs.get(name)
    if grp and grp.members:
        return ",".join(grp.members)
    return f"object:{name}"


def _parse_acl(tokens: list[str], objs: dict[str, ObjectGroup], raw: str) -> AclRule | None:
    # tokens here is the access-list line with "access-list NAME" already
    # stripped off: ["extended", "permit"/"deny", PROTO, SRC, ..., DST, ...]
    if len(tokens) < 3 or tokens[0].lower() != "extended":
        return None
    action = tokens[1].lower()
    if action not in ("permit", "deny"):
        return None
    protocol = tokens[2].lower()
    i = 3
    source, i = _consume_addr(tokens, i, objs)
    dest, i = _consume_addr(tokens, i, objs)
    dest_port = ""
    if i < len(tokens) and tokens[i].lower() in ("eq", "gt", "lt", "neq", "range"):
        op = tokens[i]
        if i + 1 < len(tokens):
            dest_port = f"{op} {tokens[i + 1]}"
    return AclRule(
        action=action,
        protocol=protocol,
        source=source,
        destination=dest,
        destination_port=dest_port,
        raw=raw,
    )


def _parse_arp_table(raw_config: str) -> list[ArpEntry]:
    """`show arp` output — unlike most vendors' ARP dump, ASA prints no
    header row at all (just `<if> <ip> <mac> <age>` per line), so instead
    of a header trigger this matches the row shape directly, anywhere in
    the pasted text: exactly 4 tokens, [0]=interface name, [1]=IP,
    [2]=MAC, [3]=digits — distinctive enough not to appear elsewhere in a
    running-config.
    """
    entries: list[ArpEntry] = []
    for line in raw_config.splitlines():
        tokens = line.strip().split()
        if len(tokens) != 4:
            continue
        iface, ip, mac, age = tokens
        if looks_like_ip(ip) and looks_like_mac(mac) and age.isdigit():
            entries.append(ArpEntry(ip=ip, mac=normalize_mac(mac), interface=iface))
    return entries


def _parse_dhcp_bindings(raw_config: str) -> list[DhcpLease]:
    """`show dhcpd binding` output — has a real header row, unlike `show arp`."""

    def _header(line: str) -> bool:
        low = line.lower()
        return "ip address" in low and "lease expir" in low

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        return DhcpLease(ip=ip, mac=mac)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


@FirewallParserRegistry.register("cisco_asa")
class CiscoASAParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        lowered = raw_config.lower()
        if "routeros" in lowered or "/interface" in lowered:
            return False
        if any(marker in lowered for marker in _DETECT_MARKERS):
            return True
        return "nameif " in lowered and "security-level" in lowered

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="cisco_asa",
            display_name="Cisco ASA",
            supported_versions="ASA 8.x - 9.x running-config text export",
            notes="Local-user secrets are one-way hashes on ASA — never recoverable, unlike IOS type-7.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        system = SystemInfo()
        interfaces: list[Interface] = []
        routes: list[Route] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        object_groups: list[ObjectGroup] = []
        local_users: list[LocalUser] = []
        objs: dict[str, ObjectGroup] = {}

        cur_iface: Interface | None = None
        cur_object: ObjectGroup | None = None

        block_openers = ("interface ", "object network ", "object-group network ")

        for raw_line in raw_config.splitlines():
            line = raw_line.rstrip("\r\n")
            stripped = line.strip()
            if not stripped:
                continue
            indented = line[:1] in (" ", "\t")

            if not indented:
                lowered_stripped = stripped.lower()
                if not lowered_stripped.startswith(block_openers):
                    cur_iface = cur_object = None

                tokens = stripped.split()
                head = tokens[0].lower()

                if head == "hostname" and len(tokens) >= 2:
                    system.hostname = tokens[1]
                elif head == "asa" and len(tokens) >= 3 and tokens[1].lower() == "version":
                    system.os_version = tokens[2]
                elif head == "interface" and len(tokens) >= 2:
                    cur_iface = Interface(name=tokens[1], status="up")
                    interfaces.append(cur_iface)
                elif head == "object" and len(tokens) >= 3 and tokens[1].lower() == "network":
                    cur_object = ObjectGroup(name=tokens[2], kind="network")
                    object_groups.append(cur_object)
                    objs[tokens[2]] = cur_object
                elif head == "object-group" and len(tokens) >= 3:
                    kind = (
                        tokens[1].lower()
                        if tokens[1].lower() in ("network", "service")
                        else "network"
                    )
                    cur_object = ObjectGroup(name=tokens[2], kind=kind)
                    object_groups.append(cur_object)
                    objs[tokens[2]] = cur_object
                elif head == "access-list" and len(tokens) >= 4:
                    rule = _parse_acl(tokens[2:], objs, stripped)
                    if rule:
                        acl_rules.append(rule)
                elif head == "route" and len(tokens) >= 5:
                    # route <if> <dest> <mask> <gateway>
                    routes.append(
                        Route(
                            destination=f"{tokens[2]}/{tokens[3]}",
                            next_hop=tokens[4],
                            interface=tokens[1],
                        )
                    )
                elif head == "nat" and len(tokens) >= 2:
                    nat_rules.append(_parse_nat(tokens, stripped))
                elif head == "username" and len(tokens) >= 2:
                    local_users.append(LocalUser(username=tokens[1], recoverable_secret=None))
                continue

            tokens = stripped.split()
            head = tokens[0].lower()

            if cur_iface is not None:
                if head == "nameif" and len(tokens) >= 2:
                    cur_iface.zone = tokens[1]
                elif head == "ip" and len(tokens) >= 3 and tokens[1].lower() == "address":
                    cur_iface.ip_address = tokens[2]
                    cur_iface.netmask = tokens[3] if len(tokens) >= 4 else ""
                    cur_iface.is_public = is_public_ip(cur_iface.ip_address)
                elif head == "description":
                    cur_iface.description = " ".join(tokens[1:])
                elif head == "shutdown":
                    cur_iface.status = "down"
                continue

            if cur_object is not None:
                if head == "host" and len(tokens) >= 2:
                    cur_object.members.append(tokens[1])
                elif head == "subnet" and len(tokens) >= 3:
                    cur_object.members.append(f"{tokens[1]}/{tokens[2]}")
                elif head == "network-object" and len(tokens) >= 2:
                    cur_object.members.append(" ".join(tokens[1:]))
                elif head == "group-object" and len(tokens) >= 2:
                    cur_object.members.append(tokens[1])
                continue

        return ParsedConfig(
            vendor="cisco_asa",
            system=system,
            interfaces=interfaces,
            routes=routes,
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=[],
            object_groups=object_groups,
            local_users=local_users,
            arp_entries=_parse_arp_table(raw_config),
            dhcp_leases=_parse_dhcp_bindings(raw_config),
        )


def _parse_nat(tokens: list[str], raw: str) -> NatRule:
    # nat (inside,outside) source static OBJ_IN OBJ_OUT
    # nat (inside,outside) source dynamic OBJ_IN interface
    kind = "static" if "static" in (t.lower() for t in tokens) else "dynamic"
    try:
        idx = next(i for i, t in enumerate(tokens) if t.lower() in ("static", "dynamic"))
    except StopIteration:
        return NatRule(kind=kind, raw=raw)
    inside = tokens[idx + 1] if idx + 1 < len(tokens) else ""
    outside = tokens[idx + 2] if kind == "static" and idx + 2 < len(tokens) else ""
    return NatRule(kind=kind, inside_address=inside, outside_address=outside, raw=raw)
