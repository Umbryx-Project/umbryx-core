"""
PaloAlto PAN-OS `set`-format config export parser.

PAN-OS natively stores config as XML, but the artifact operators actually
pull off a device (`show config running` piped through `set` formatting,
or `> configure` / `# set ...` from `load config from running-config.xml`)
is flat `set <path...> <value>` lines — so this parser is line-based like
the Cisco ones, not structured, despite PAN-OS's native format being XML.

Each `set` line is a keyword path; values are captured between one
recognized keyword and the next. `set mgt-config users X phash <hash>` is
a one-way hash — never recoverable.
"""

from __future__ import annotations

from .base import FirewallConfigParser, FirewallParserRegistry
from .schema import (
    AclRule,
    ArpEntry,
    Interface,
    LocalUser,
    NatRule,
    ObjectGroup,
    ParsedConfig,
    Route,
    SystemInfo,
    VendorInfo,
)
from .util import extract_ip_and_mac, is_public_ip, scan_operational_table

_DETECT_MARKERS = (
    "set deviceconfig system hostname",
    "set network interface ethernet",
    "set rulebase security rules",
    "set mgt-config users",
)

# Keywords that terminate the "value" span of a preceding keyword when
# walking a `set` line — e.g. in `... source any destination any action
# allow`, "destination" ends the "source" value and "action" ends
# "destination"'s.
_RULE_KEYWORDS = (
    "from",
    "to",
    "source",
    "destination",
    "application",
    "service",
    "action",
    "source-translation",
    "destination-translation",
    "translated-address",
    "static-ip",
    "dynamic-ip-and-port",
)


def _extract_after(tokens: list[str], keyword: str, stop_words: tuple[str, ...]) -> str:
    try:
        idx = tokens.index(keyword)
    except ValueError:
        return ""
    vals = []
    for tok in tokens[idx + 1 :]:
        if tok in stop_words:
            break
        vals.append(tok)
    return " ".join(vals)


def _parse_arp_table(raw_config: str) -> list[ArpEntry]:
    """`show arp all` operational-mode output — header carries 'mac' and
    'status' columns (PAN-OS CLI headers are lowercase, unlike most other
    vendors')."""

    def _header(line: str) -> bool:
        low = line.lower()
        return "mac" in low and "status" in low and "interface" in low

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        iface = tokens[0] if tokens and tokens[0] not in (ip, mac) else ""
        return ArpEntry(ip=ip, mac=mac, interface=iface)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


@FirewallParserRegistry.register("paloalto")
class PaloAltoParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        lowered = raw_config.lower()
        return lowered.lstrip().startswith("set ") and any(
            marker in lowered for marker in _DETECT_MARKERS
        )

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="paloalto",
            display_name="PaloAlto PAN-OS",
            supported_versions="PAN-OS 9.x - 11.x `set`-format config export",
            notes="mgt-config user `phash` secrets are one-way hashes — never recoverable.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        system = SystemInfo()
        iface_by_name: dict[str, Interface] = {}
        route_by_name: dict[str, Route] = {}
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        object_groups: list[ObjectGroup] = []
        local_users: list[LocalUser] = []

        for raw_line in raw_config.splitlines():
            stripped = raw_line.strip()
            if not stripped.lower().startswith("set "):
                continue
            tokens = stripped.split()
            if len(tokens) < 2:
                continue

            if tokens[1] == "deviceconfig" and "hostname" in tokens:
                idx = tokens.index("hostname")
                if idx + 1 < len(tokens):
                    system.hostname = tokens[idx + 1]

            elif tokens[1] == "network" and len(tokens) >= 3 and tokens[2] == "interface":
                # set network interface ethernet <name> layer3 ip <ip>/<prefix>
                try:
                    name_idx = tokens.index("ethernet") + 1
                    name = tokens[name_idx]
                except (ValueError, IndexError):
                    continue
                iface = iface_by_name.setdefault(name, Interface(name=name, status="up"))
                if "ip" in tokens:
                    ip_idx = tokens.index("ip")
                    if ip_idx + 1 < len(tokens):
                        addr = tokens[ip_idx + 1]
                        ip, _, prefix = addr.partition("/")
                        iface.ip_address = ip
                        iface.netmask = prefix
                        iface.is_public = is_public_ip(ip)

            elif tokens[1] == "network" and len(tokens) >= 3 and tokens[2] == "virtual-router":
                # set network virtual-router <vr> routing-table ip static-route <name> destination <cidr>
                # set network virtual-router <vr> routing-table ip static-route <name> nexthop ip-address <ip>
                if "static-route" in tokens:
                    sr_idx = tokens.index("static-route")
                    rname = tokens[sr_idx + 1] if sr_idx + 1 < len(tokens) else ""
                    route = route_by_name.setdefault(rname, Route(destination="0.0.0.0/0"))
                    if "destination" in tokens:
                        d_idx = tokens.index("destination")
                        if d_idx + 1 < len(tokens):
                            route.destination = tokens[d_idx + 1]
                    if "ip-address" in tokens:
                        ip_idx = tokens.index("ip-address")
                        if ip_idx + 1 < len(tokens):
                            route.next_hop = tokens[ip_idx + 1]

            elif tokens[1] == "address-object" and len(tokens) >= 3:
                name = tokens[2]
                cidr = ""
                if "ip-netmask" in tokens:
                    idx = tokens.index("ip-netmask")
                    if idx + 1 < len(tokens):
                        cidr = tokens[idx + 1]
                object_groups.append(
                    ObjectGroup(name=name, kind="network", members=[cidr] if cidr else [])
                )

            elif tokens[1] == "rulebase" and len(tokens) >= 3 and tokens[2] == "security":
                action = _extract_after(tokens, "action", _RULE_KEYWORDS)
                source = _extract_after(tokens, "source", _RULE_KEYWORDS) or "any"
                dest = _extract_after(tokens, "destination", _RULE_KEYWORDS) or "any"
                service = _extract_after(tokens, "service", _RULE_KEYWORDS) or "any"
                acl_rules.append(
                    AclRule(
                        action="permit" if action == "allow" else ("deny" if action else "permit"),
                        protocol=service,
                        source=source,
                        destination=dest,
                        raw=stripped,
                    )
                )

            elif tokens[1] == "rulebase" and len(tokens) >= 3 and tokens[2] == "nat":
                outside = _extract_after(tokens, "translated-address", _RULE_KEYWORDS)
                kind = "dynamic" if "dynamic-ip-and-port" in tokens else "static"
                if outside:
                    nat_rules.append(NatRule(kind=kind, outside_address=outside, raw=stripped))

            elif tokens[1] == "mgt-config" and "users" in tokens:
                idx = tokens.index("users")
                if idx + 1 < len(tokens):
                    local_users.append(LocalUser(username=tokens[idx + 1], recoverable_secret=None))

        return ParsedConfig(
            vendor="paloalto",
            system=system,
            interfaces=list(iface_by_name.values()),
            routes=list(route_by_name.values()),
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=[],
            object_groups=object_groups,
            local_users=local_users,
            arp_entries=_parse_arp_table(raw_config),
        )
