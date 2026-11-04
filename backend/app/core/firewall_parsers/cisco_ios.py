"""
Cisco IOS / IOS-XE running-config parser.

Reference implementation for the FirewallConfigParser interface — the first
vendor implemented (per the project's stated priority: most common format).
Cisco ASA uses different ACL/NAT syntax (`nameif`, `access-group`, `object
network` with `nat` sub-commands) and is NOT covered here — a distinct
parser would be needed for ASA.

Parsing is a single-pass, indentation-aware line scanner using only
str.split()/startswith() and simple non-backtracking checks — no regex with
nested quantifiers, so a hostile/malformed config cannot trigger
catastrophic backtracking (ReDoS).
"""

from __future__ import annotations

import ipaddress

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
    Vlan,
)
from .util import extract_ip_and_mac, is_public_ip, scan_operational_table

_DETECT_MARKERS = (
    "interface gigabitethernet",
    "interface fastethernet",
    "interface tengigabitethernet",
    "interface vlan",
    "ip access-list extended",
    "ip access-list standard",
    "boot system flash",
)

# Cisco type-7 "password encryption" is a fixed, publicly-documented XOR
# substitution table — not real encryption. Trivially reversible by design,
# which is exactly why it must be treated as a plaintext-equivalent secret
# (spec §5) rather than left in the parsed config.
_TYPE7_XLAT = [
    0x64,
    0x73,
    0x66,
    0x64,
    0x3B,
    0x6B,
    0x66,
    0x6F,
    0x41,
    0x2C,
    0x2E,
    0x69,
    0x79,
    0x65,
    0x77,
    0x72,
    0x6B,
    0x6C,
    0x64,
    0x4A,
    0x4B,
    0x44,
    0x48,
    0x53,
    0x55,
    0x42,
    0x73,
    0x67,
    0x76,
    0x63,
    0x61,
    0x36,
    0x39,
    0x38,
    0x33,
    0x34,
    0x6E,
    0x63,
    0x78,
    0x76,
    0x39,
    0x38,
    0x37,
    0x33,
    0x32,
    0x35,
    0x34,
    0x6B,
    0x3B,
    0x66,
    0x67,
    0x38,
    0x37,
]


def _decode_type7(enc: str) -> str | None:
    enc = enc.strip()
    if len(enc) < 4 or not enc[:2].isdigit():
        return None
    hex_pairs = enc[2:]
    if len(hex_pairs) % 2 != 0:
        return None
    try:
        seed = int(enc[:2])
        out = []
        for i in range(0, len(hex_pairs), 2):
            byte = int(hex_pairs[i : i + 2], 16)
            xlat = _TYPE7_XLAT[(seed + i // 2) % len(_TYPE7_XLAT)]
            out.append(chr(byte ^ xlat))
        return "".join(out)
    except ValueError:
        return None


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _consume_addr(tokens: list[str], i: int) -> tuple[str, int]:
    if i >= len(tokens):
        return "any", i
    tok = tokens[i]
    if tok == "any":
        return "any", i + 1
    if tok == "host" and i + 1 < len(tokens):
        return tokens[i + 1], i + 2
    if tok == "object-group" and i + 1 < len(tokens):
        return f"object-group:{tokens[i + 1]}", i + 2
    if i + 1 < len(tokens) and _looks_like_ip(tokens[i + 1]):
        return f"{tok}/{tokens[i + 1]}", i + 2
    return tok, i + 1


def _resolve_group(value: str, objgroup_by_name: dict[str, ObjectGroup]) -> str:
    if not value.startswith("object-group:"):
        return value
    name = value.split(":", 1)[1]
    grp = objgroup_by_name.get(name)
    if grp and grp.members:
        return ",".join(grp.members)
    return f"group:{name}"


def _parse_acl_tokens(
    tokens: list[str], objgroup_by_name: dict[str, ObjectGroup], raw: str
) -> AclRule | None:
    if len(tokens) < 2:
        return None
    action = tokens[0].lower()
    if action not in ("permit", "deny"):
        return None
    protocol = tokens[1].lower()
    i = 2
    source, i = _consume_addr(tokens, i)
    dest, i = _consume_addr(tokens, i)
    dest_port = ""
    if i < len(tokens) and tokens[i].lower() in ("eq", "gt", "lt", "neq", "range"):
        op = tokens[i]
        if i + 1 < len(tokens):
            dest_port = f"{op} {tokens[i + 1]}"
    return AclRule(
        action=action,
        protocol=protocol,
        source=_resolve_group(source, objgroup_by_name),
        destination=_resolve_group(dest, objgroup_by_name),
        destination_port=dest_port,
        raw=raw,
    )


def _parse_nat(tokens: list[str]) -> NatRule | None:
    # ip nat inside source static <inside> <outside>
    # ip nat inside source list <acl> interface <iface> overload   (dynamic/PAT)
    if len(tokens) < 5:
        return None
    kind_tok = tokens[4].lower()
    raw = " ".join(tokens)
    if kind_tok == "static" and len(tokens) >= 7:
        return NatRule(kind="static", inside_address=tokens[5], outside_address=tokens[6], raw=raw)
    return NatRule(kind="dynamic", inside_address=" ".join(tokens[4:]), raw=raw)


def _parse_username(tokens: list[str]) -> LocalUser | None:
    if len(tokens) < 2:
        return None
    username = tokens[1]
    secret = None
    for idx, tok in enumerate(tokens):
        tl = tok.lower()
        if tl in ("password", "secret") and idx + 1 < len(tokens):
            nxt = tokens[idx + 1]
            if nxt == "7" and idx + 2 < len(tokens):
                secret = _decode_type7(tokens[idx + 2])
            elif nxt == "0" and idx + 2 < len(tokens):
                secret = tokens[idx + 2]
            # type 5 (MD5) / bare hash — not recoverable, leave secret=None
            break
    return LocalUser(username=username, recoverable_secret=secret)


def _parse_arp_table(raw_config: str) -> list[ArpEntry]:
    """`show ip arp` output pasted after (or alongside) the running-config.
    Header: 'Protocol  Address  Age (min)  Hardware Addr  Type  Interface'.
    """

    def _header(line: str) -> bool:
        low = line.lower()
        return "protocol" in low and "hardware addr" in low

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        iface = tokens[-1] if tokens and tokens[-1] not in (ip, mac) else ""
        return ArpEntry(ip=ip, mac=mac, interface=iface)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


def _parse_dhcp_bindings(raw_config: str) -> list[DhcpLease]:
    """`show ip dhcp binding` output — no hostname column in classic IOS
    output, so only ip/mac are recovered."""

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


@FirewallParserRegistry.register("cisco_ios")
class CiscoIOSParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        lowered = raw_config.lower()
        if "routeros" in lowered or "/interface" in lowered:
            return False
        # ASA and Huawei VRP both name interfaces "GigabitEthernetX" too,
        # which would otherwise match _DETECT_MARKERS — their own
        # unambiguous markers must win.
        if "nameif " in lowered or "asa version" in lowered or ": saved" in lowered:
            return False
        if "sysname " in lowered or "acl number" in lowered:
            return False
        return any(marker in lowered for marker in _DETECT_MARKERS)

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="cisco_ios",
            display_name="Cisco IOS / IOS-XE",
            supported_versions="12.x - 17.x running-config text export",
            notes="Cisco ASA uses different ACL/NAT syntax and is not covered by this parser.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        system = SystemInfo()
        interfaces: list[Interface] = []
        routes: list[Route] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        vlans: list[Vlan] = []
        object_groups: list[ObjectGroup] = []
        local_users: list[LocalUser] = []
        objgroup_by_name: dict[str, ObjectGroup] = {}

        cur_iface: Interface | None = None
        cur_acl_name: str | None = None
        cur_objgroup: ObjectGroup | None = None
        cur_vlan: Vlan | None = None

        block_openers = (
            "interface ",
            "ip access-list extended ",
            "ip access-list standard ",
            "object-group network ",
            "object-group service ",
            "vlan ",
        )

        for raw_line in raw_config.splitlines():
            line = raw_line.rstrip("\r\n")
            stripped = line.strip()
            if not stripped:
                continue
            indented = line[:1] in (" ", "\t")

            if stripped == "!":
                cur_iface = cur_acl_name = cur_objgroup = cur_vlan = None
                continue

            if not indented:
                lowered_stripped = stripped.lower()
                if not lowered_stripped.startswith(block_openers):
                    cur_iface = cur_acl_name = cur_objgroup = cur_vlan = None

                tokens = stripped.split()
                head = tokens[0].lower()

                if head == "hostname" and len(tokens) >= 2:
                    system.hostname = tokens[1]
                elif head == "version" and len(tokens) >= 2:
                    system.os_version = tokens[1]
                elif head == "interface" and len(tokens) >= 2:
                    cur_iface = Interface(name=tokens[1], status="up")
                    interfaces.append(cur_iface)
                elif (
                    head == "ip"
                    and len(tokens) >= 2
                    and tokens[1].lower() == "route"
                    and len(tokens) >= 5
                ):
                    routes.append(Route(destination=f"{tokens[2]}/{tokens[3]}", next_hop=tokens[4]))
                elif head == "ip" and len(tokens) >= 4 and tokens[1].lower() == "access-list":
                    cur_acl_name = tokens[3]
                elif head == "ip" and len(tokens) >= 5 and tokens[1].lower() == "nat":
                    nat_rule = _parse_nat(tokens)
                    if nat_rule:
                        nat_rules.append(nat_rule)
                elif head == "access-list" and len(tokens) >= 4:
                    rule = _parse_acl_tokens(tokens[2:], objgroup_by_name, stripped)
                    if rule:
                        acl_rules.append(rule)
                elif head == "object-group" and len(tokens) >= 3:
                    kind = (
                        tokens[1].lower()
                        if tokens[1].lower() in ("network", "service")
                        else "network"
                    )
                    cur_objgroup = ObjectGroup(name=tokens[2], kind=kind)
                    object_groups.append(cur_objgroup)
                    objgroup_by_name[tokens[2]] = cur_objgroup
                elif head == "vlan" and len(tokens) >= 2 and tokens[1].isdigit():
                    cur_vlan = Vlan(vlan_id=tokens[1])
                    vlans.append(cur_vlan)
                elif head == "username" and len(tokens) >= 2:
                    user = _parse_username(tokens)
                    if user:
                        local_users.append(user)
                continue

            tokens = stripped.split()
            head = tokens[0].lower()

            if cur_iface is not None:
                if head == "description":
                    cur_iface.description = " ".join(tokens[1:])
                elif head == "ip" and len(tokens) >= 3 and tokens[1].lower() == "address":
                    cur_iface.ip_address = tokens[2]
                    cur_iface.netmask = tokens[3] if len(tokens) >= 4 else ""
                    cur_iface.is_public = is_public_ip(cur_iface.ip_address)
                elif (
                    head == "switchport"
                    and len(tokens) >= 4
                    and tokens[1].lower() == "access"
                    and tokens[2].lower() == "vlan"
                ):
                    cur_iface.vlan = tokens[3]
                elif head == "shutdown":
                    cur_iface.status = "down"
                continue

            if cur_acl_name is not None:
                if head in ("permit", "deny"):
                    rule = _parse_acl_tokens(
                        tokens, objgroup_by_name, f"{cur_acl_name}: {stripped}"
                    )
                    if rule:
                        acl_rules.append(rule)
                continue

            if cur_objgroup is not None:
                if head in (
                    "network-object",
                    "host",
                    "group-object",
                    "service-object",
                    "port-object",
                ):
                    cur_objgroup.members.append(
                        " ".join(tokens[1:]) if len(tokens) > 1 else stripped
                    )
                continue

            if cur_vlan is not None:
                if head == "name" and len(tokens) >= 2:
                    cur_vlan.name = tokens[1]
                continue

        return ParsedConfig(
            vendor="cisco_ios",
            system=system,
            interfaces=interfaces,
            routes=routes,
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=vlans,
            object_groups=object_groups,
            local_users=local_users,
            arp_entries=_parse_arp_table(raw_config),
            dhcp_leases=_parse_dhcp_bindings(raw_config),
        )
