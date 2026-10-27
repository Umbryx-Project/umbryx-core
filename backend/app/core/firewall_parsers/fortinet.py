"""
FortiOS (`show full-configuration`) parser.

FortiOS uses a nested `config <section>` / `edit "<name>"` / `set key
value...` / `next` / `end` block structure — a different shape from the
flat Cisco line style, so this parser walks a small explicit stack
instead of the indentation-based approach the line-oriented vendors use.
Still no regex: quoted values are split with a linear scan
(`_split_line`) so malformed/adversarial input can't trigger catastrophic
backtracking.

`config system admin` passwords are always `set password ENC <blob>` —
FortiOS never stores a reversible local admin secret — recoverable_secret
is always None.
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
    SystemInfo,
    VendorInfo,
)
from .util import extract_ip_and_mac, is_public_ip, scan_operational_table

_DETECT_MARKERS = (
    "#config-version=",
    "config system interface",
    "config firewall policy",
)


def _split_line(s: str) -> list[str]:
    """Quote-aware whitespace split — no regex."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] == " ":
            i += 1
        if i >= n:
            break
        if s[i] == '"':
            i += 1
            start = i
            while i < n and s[i] != '"':
                i += 1
            out.append(s[start:i])
            i += 1
        else:
            start = i
            while i < n and s[i] != " ":
                i += 1
            out.append(s[start:i])
    return out


def _parse_arp_table(raw_config: str) -> list[ArpEntry]:
    """`get system arp` output. Header carries 'Hardware Addr' (also true
    of Cisco IOS's header, which is fine — vendor is already fixed by
    detect() by the time this runs)."""

    def _header(line: str) -> bool:
        return "hardware addr" in line.lower()

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        iface = tokens[-1] if tokens and tokens[-1] not in (ip, mac) else ""
        return ArpEntry(ip=ip, mac=mac, interface=iface)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


def _parse_dhcp_leases(raw_config: str) -> list[DhcpLease]:
    """`get system dhcp lease-list <interface>` output — header carries
    'MAC' and 'HOSTNAME'; hostname is always the last column regardless of
    how many tokens the lease-expiry timestamp splits into."""

    def _header(line: str) -> bool:
        up = line.upper()
        return "MAC" in up and "HOSTNAME" in up

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        hostname = tokens[-1] if tokens and tokens[-1] not in (ip, mac) else ""
        return DhcpLease(ip=ip, mac=mac, hostname=hostname)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


@FirewallParserRegistry.register("fortinet")
class FortinetParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        lowered = raw_config.lower()
        return any(marker in lowered for marker in _DETECT_MARKERS)

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="fortinet",
            display_name="Fortinet FortiOS",
            supported_versions="FortiOS 6.x / 7.x `show full-configuration` text export",
            notes="Admin passwords (`ENC` blobs) are never recoverable.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        system = SystemInfo()
        interfaces: list[Interface] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        local_users: list[LocalUser] = []

        # Stack of (section_name, entity_name_or_None). `config`/`edit` push,
        # `next`/`end` pop — mirrors FortiOS's own block nesting exactly.
        stack: list[tuple[str, str]] = []
        cur_kv: dict[str, list[str]] = {}
        cur_iface: Interface | None = None

        def section() -> str:
            return stack[-1][0] if stack else ""

        def entity() -> str:
            return stack[-1][1] if stack else ""

        def flush_entity():
            nonlocal cur_iface
            sec = section()
            name = entity()
            # Guard on `name`: "end" closes a `config` section even when no
            # `edit` ever ran inside it (e.g. `config system global` has no
            # entities at all) — without this guard that also fires this
            # function, and firewall policy/vip/admin would spuriously emit
            # an empty deny-all rule from a never-populated cur_kv.
            if not name:
                cur_kv.clear()
                return
            if sec == "system interface":
                pass  # committed incrementally onto cur_iface below
            elif sec == "firewall policy":
                action = cur_kv.get("action", ["deny"])[0]
                acl_rules.append(
                    AclRule(
                        action="permit" if action == "accept" else "deny",
                        protocol=" ".join(cur_kv.get("service", ["any"])),
                        source=" ".join(cur_kv.get("srcaddr", ["any"])),
                        destination=" ".join(cur_kv.get("dstaddr", ["any"])),
                        interface=" ".join(cur_kv.get("srcintf", [""])),
                        direction=" ".join(cur_kv.get("dstintf", [""])),
                        raw=f"policy {name}: action={action}",
                    )
                )
            elif sec == "firewall vip" and "extip" in cur_kv:
                nat_rules.append(
                    NatRule(
                        kind="static",
                        outside_address=" ".join(cur_kv.get("extip", [])),
                        inside_address=" ".join(cur_kv.get("mappedip", [])),
                        outside_port=" ".join(cur_kv.get("extport", [])),
                        inside_port=" ".join(cur_kv.get("mappedport", [])),
                        raw=f"vip {name}",
                    )
                )
            elif sec == "system admin":
                local_users.append(LocalUser(username=name, recoverable_secret=None))
            cur_kv.clear()

        for raw_line in raw_config.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens = _split_line(stripped)
            if not tokens:
                continue
            head = tokens[0].lower()

            if head == "config" and len(tokens) >= 2:
                stack.append((" ".join(tokens[1:]).lower(), ""))
                continue
            if head == "edit" and len(tokens) >= 2:
                name = tokens[1]
                if stack:
                    stack[-1] = (stack[-1][0], name)
                if section() == "system interface":
                    cur_iface = Interface(name=name, status="up")
                    interfaces.append(cur_iface)
                cur_kv.clear()
                continue
            if head == "next":
                flush_entity()
                if stack:
                    stack[-1] = (stack[-1][0], "")
                cur_iface = None
                continue
            if head == "end":
                flush_entity()
                if stack:
                    stack.pop()
                cur_iface = None
                continue
            if head == "set" and len(tokens) >= 2:
                key = tokens[1].lower()
                values = tokens[2:]
                cur_kv[key] = values
                if section() == "system global" and key == "hostname" and values:
                    system.hostname = values[0]
                elif section() == "system interface" and cur_iface is not None:
                    if key == "ip" and values:
                        cur_iface.ip_address = values[0]
                        cur_iface.netmask = values[1] if len(values) > 1 else ""
                        cur_iface.is_public = is_public_ip(cur_iface.ip_address)
                    elif key == "vlanid" and values:
                        cur_iface.vlan = values[0]
                    elif key == "status" and values and values[0] == "down":
                        cur_iface.status = "down"
                continue

        return ParsedConfig(
            vendor="fortinet",
            system=system,
            interfaces=interfaces,
            routes=[],
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=[],
            object_groups=[],
            local_users=local_users,
            arp_entries=_parse_arp_table(raw_config),
            dhcp_leases=_parse_dhcp_leases(raw_config),
        )
