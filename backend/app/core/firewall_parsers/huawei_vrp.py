"""
Huawei VRP (`display current-configuration`) parser.

VRP uses `#` as the section terminator (Cisco IOS uses `!`) and numbered
ACLs (`acl number NNNN`) with permit/deny rules that carry an explicit
wildcard mask on the source, mirroring IOS ACL semantics closely enough
that the same tokenizing approach applies. `local-user ... password
irreversible-cipher <hash>` is a one-way hash — never recoverable;
`password simple <text>` (older VRP releases) is cleartext in the config
itself, so it is recoverable as-is.

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
    ParsedConfig,
    Route,
    SystemInfo,
    VendorInfo,
    Vlan,
)
from .util import extract_ip_and_mac, is_public_ip, scan_operational_table

_DETECT_MARKERS = (
    "sysname ",
    "acl number",
    "display current-configuration",
)


def _parse_acl_rule(tokens: list[str], raw: str) -> AclRule | None:
    # rule N {permit|deny} PROTO [source SRC [WILDCARD|any]] [destination DST [WILDCARD|any]]
    #   [destination-port eq PORT]
    if len(tokens) < 3 or not tokens[0].isdigit():
        return None
    action = tokens[1].lower()
    if action not in ("permit", "deny"):
        return None
    protocol = tokens[2].lower()
    source = "any"
    destination = "any"
    dest_port = ""
    i = 3
    while i < len(tokens):
        tok = tokens[i].lower()
        if tok == "source" and i + 1 < len(tokens):
            if tokens[i + 1] == "any":
                source = "any"
                i += 2
            elif i + 2 < len(tokens):
                source = f"{tokens[i + 1]}/{tokens[i + 2]}"
                i += 3
            else:
                i += 2
        elif tok == "destination" and i + 1 < len(tokens):
            if tokens[i + 1] == "any":
                destination = "any"
                i += 2
            elif i + 2 < len(tokens) and not tokens[i + 2].lower().startswith("destination-port"):
                destination = f"{tokens[i + 1]}/{tokens[i + 2]}"
                i += 3
            else:
                i += 2
        elif tok == "destination-port" and i + 2 < len(tokens):
            dest_port = f"{tokens[i + 1]} {tokens[i + 2]}"
            i += 3
        else:
            i += 1
    return AclRule(
        action=action,
        protocol=protocol,
        source=source,
        destination=destination,
        destination_port=dest_port,
        raw=raw,
    )


def _parse_arp_table(raw_config: str) -> list[ArpEntry]:
    """`display arp` output. Header: 'IP ADDRESS  MAC ADDRESS  EXPIRE(M) TYPE INTERFACE'."""

    def _header(line: str) -> bool:
        up = line.upper()
        return "IP ADDRESS" in up and "MAC ADDRESS" in up

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        iface = tokens[-1] if tokens and tokens[-1] not in (ip, mac) else ""
        return ArpEntry(ip=ip, mac=mac, interface=iface)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


def _parse_dhcp_leases(raw_config: str) -> list[DhcpLease]:
    """`display dhcp server ip-in-use all` output. Header carries 'MAC'
    and 'LEASE' (distinguishes it from the ARP header above, which has
    neither)."""

    def _header(line: str) -> bool:
        up = line.upper()
        return "MAC" in up and "LEASE" in up

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        return DhcpLease(ip=ip, mac=mac)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


@FirewallParserRegistry.register("huawei_vrp")
class HuaweiVRPParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        lowered = raw_config.lower()
        if "routeros" in lowered or "/interface" in lowered:
            return False
        if "ciscoasa" in lowered or "ip access-list extended" in lowered:
            return False
        return any(marker in lowered for marker in _DETECT_MARKERS)

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="huawei_vrp",
            display_name="Huawei VRP",
            supported_versions="VRP 5.x / 8.x `display current-configuration` text export",
            notes="Only `password simple <text>` is recoverable; `irreversible-cipher` secrets are one-way hashes.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        system = SystemInfo()
        interfaces: list[Interface] = []
        routes: list[Route] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        vlans: list[Vlan] = []
        local_users: list[LocalUser] = []

        cur_iface: Interface | None = None
        cur_acl_name: str | None = None

        block_openers = ("interface ", "acl number ", "acl ")

        for raw_line in raw_config.splitlines():
            line = raw_line.rstrip("\r\n")
            stripped = line.strip()
            if not stripped:
                continue
            indented = line[:1] in (" ", "\t")

            if stripped == "#":
                cur_iface = cur_acl_name = None
                continue

            if not indented:
                lowered_stripped = stripped.lower()
                if not lowered_stripped.startswith(block_openers):
                    cur_iface = cur_acl_name = None

                tokens = stripped.split()
                head = tokens[0].lower()

                if head == "sysname" and len(tokens) >= 2:
                    system.hostname = tokens[1]
                elif head == "interface" and len(tokens) >= 2:
                    cur_iface = Interface(name=tokens[1], status="up")
                    interfaces.append(cur_iface)
                elif (
                    head == "ip"
                    and len(tokens) >= 3
                    and tokens[1].lower() == "route-static"
                    and len(tokens) >= 5
                ):
                    routes.append(Route(destination=f"{tokens[2]}/{tokens[3]}", next_hop=tokens[4]))
                elif head == "acl" and "number" in (t.lower() for t in tokens) and len(tokens) >= 3:
                    cur_acl_name = tokens[2]
                elif head == "vlan" and len(tokens) >= 2 and tokens[1].lower() == "batch":
                    for vid in tokens[2:]:
                        if vid.isdigit():
                            vlans.append(Vlan(vlan_id=vid))
                elif (
                    head == "nat"
                    and len(tokens) >= 2
                    and tokens[1].lower() == "address-group"
                    and len(tokens) >= 4
                ):
                    nat_rules.append(
                        NatRule(kind="dynamic", outside_address=tokens[3], raw=stripped)
                    )
                elif head == "local-user" and len(tokens) >= 2:
                    username = tokens[1]
                    secret = None
                    if "password" in (t.lower() for t in tokens):
                        idx = next(i for i, t in enumerate(tokens) if t.lower() == "password")
                        if (
                            idx + 1 < len(tokens)
                            and tokens[idx + 1].lower() == "simple"
                            and idx + 2 < len(tokens)
                        ):
                            secret = tokens[idx + 2]
                    local_users.append(LocalUser(username=username, recoverable_secret=secret))
                continue

            tokens = stripped.split()
            head = tokens[0].lower()

            if cur_iface is not None:
                if head == "ip" and len(tokens) >= 3 and tokens[1].lower() == "address":
                    cur_iface.ip_address = tokens[2]
                    cur_iface.netmask = tokens[3] if len(tokens) >= 4 else ""
                    cur_iface.is_public = is_public_ip(cur_iface.ip_address)
                elif head == "description":
                    cur_iface.description = " ".join(tokens[1:])
                elif head == "shutdown":
                    cur_iface.status = "down"
                continue

            if cur_acl_name is not None and head == "rule":
                # tokens[0] is the literal keyword "rule" — _parse_acl_rule
                # expects the rule number first.
                rule = _parse_acl_rule(tokens[1:], f"{cur_acl_name}: {stripped}")
                if rule:
                    acl_rules.append(rule)
                continue

        return ParsedConfig(
            vendor="huawei_vrp",
            system=system,
            interfaces=interfaces,
            routes=routes,
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=vlans,
            object_groups=[],
            local_users=local_users,
            arp_entries=_parse_arp_table(raw_config),
            dhcp_leases=_parse_dhcp_leases(raw_config),
        )
