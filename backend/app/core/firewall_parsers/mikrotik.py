"""
MikroTik RouterOS `/export` config parser.

RouterOS export syntax is section-based: a line starting with `/` selects a
config path (e.g. `/ip firewall filter`), followed by `add`/`set` lines
carrying `key=value` pairs (values may be quoted to include spaces). Long
lines are wrapped with a trailing backslash and continued on the next,
indented line.

Parsing uses a hand-written linear key=value tokenizer (no regex) so a
malformed/adversarial export can't trigger pathological backtracking.
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
    "by routeros",
    "/ip firewall filter",
    "/ip firewall nat",
    "/interface bridge",
    "/system identity",
)

_ACTION_MAP = {"accept": "permit", "allow": "permit", "drop": "deny", "reject": "deny"}


def _join_continuations(raw_config: str) -> list[str]:
    lines = raw_config.splitlines()
    out: list[str] = []
    buf = ""
    for line in lines:
        if buf:
            line = buf + " " + line.strip()
            buf = ""
        if line.endswith("\\"):
            buf = line[:-1].rstrip()
            continue
        out.append(line)
    if buf:
        out.append(buf)
    return out


def _tokenize_kv(s: str) -> dict[str, str]:
    """Linear scan of `key=value key2="quoted value" flagword` — O(len(s)),
    no regex, so it can't be driven into catastrophic backtracking."""
    tokens: dict[str, str] = {}
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] == " ":
            i += 1
        if i >= n:
            break
        start = i
        while i < n and s[i] not in " =":
            i += 1
        key = s[start:i]
        if not key:
            i += 1
            continue
        if i < n and s[i] == "=":
            i += 1
            if i < n and s[i] == '"':
                i += 1
                vstart = i
                while i < n and s[i] != '"':
                    i += 1
                value = s[vstart:i]
                i += 1
            else:
                vstart = i
                while i < n and s[i] != " ":
                    i += 1
                value = s[vstart:i]
            tokens[key] = value
        else:
            tokens[key] = ""
    return tokens


def _split_address(addr: str) -> tuple[str, str]:
    if "/" in addr:
        ip, _, prefix = addr.partition("/")
        return ip, prefix
    return addr, ""


def _parse_arp_table(raw_config: str) -> list[ArpEntry]:
    """`/ip arp print` output — header row has 'ADDRESS' + 'MAC-ADDRESS'
    columns. Must explicitly exclude 'HOST-NAME' or this also matches the
    DHCP-lease header below (same two columns plus one more), which would
    otherwise misparse that block's rows as ARP entries too."""

    def _header(line: str) -> bool:
        up = line.upper()
        return "ADDRESS" in up and "MAC-ADDRESS" in up and "HOST-NAME" not in up

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        iface = tokens[-1] if tokens and tokens[-1] not in (ip, mac) else ""
        return ArpEntry(ip=ip, mac=mac, interface=iface)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


def _parse_dhcp_leases(raw_config: str) -> list[DhcpLease]:
    """`/ip dhcp-server lease print` output — header additionally has a
    'HOST-NAME' column, which the client self-reports."""

    def _header(line: str) -> bool:
        up = line.upper()
        return "ADDRESS" in up and "MAC-ADDRESS" in up and "HOST-NAME" in up

    def _row(tokens: list[str]):
        pair = extract_ip_and_mac(tokens)
        if not pair:
            return None
        ip, mac = pair
        # Layout is "... ADDRESS MAC-ADDRESS HOST-NAME SERVER" — the
        # hostname is whatever sits right after the MAC token.
        hostname = ""
        for i, t in enumerate(tokens):
            if t.replace(":", "").lower() == mac.replace(":", ""):
                if i + 1 < len(tokens) - 1:  # leave the trailing SERVER column out
                    hostname = tokens[i + 1]
                break
        return DhcpLease(ip=ip, mac=mac, hostname=hostname)

    return scan_operational_table(raw_config.splitlines(), _header, _row)


@FirewallParserRegistry.register("mikrotik")
class MikroTikParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        lowered = raw_config.lower()
        return any(marker in lowered for marker in _DETECT_MARKERS)

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="mikrotik",
            display_name="MikroTik RouterOS",
            supported_versions="RouterOS 6.x / 7.x (`/export` text output)",
            notes="Local user passwords are not present in plaintext-recoverable form in `/export` output.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        system = SystemInfo()
        iface_by_name: dict[str, Interface] = {}
        routes: list[Route] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        vlans: list[Vlan] = []
        local_users: list[LocalUser] = []

        cur_section = ""

        for line in _join_continuations(raw_config):
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("#"):
                low = stripped.lower()
                if "by routeros" in low:
                    idx = low.find("routeros")
                    system.os_version = stripped[idx:].split()[-1] if idx != -1 else ""
                continue

            if stripped.startswith("/"):
                cur_section = stripped[1:].strip().lower()
                continue

            if not (
                stripped.startswith("add ")
                or stripped.startswith("add")
                or stripped.startswith("set ")
            ):
                continue

            verb, _, rest = stripped.partition(" ")
            kv = _tokenize_kv(rest)

            if (
                cur_section.startswith("interface")
                and cur_section != "interface vlan"
                and "name" in kv
            ):
                name = kv["name"]
                iface = iface_by_name.setdefault(name, Interface(name=name))
                iface.description = kv.get("comment", iface.description)
                iface.status = "down" if kv.get("disabled", "no") == "yes" else "up"

            elif cur_section == "interface vlan" and "name" in kv:
                name = kv["name"]
                iface = iface_by_name.setdefault(name, Interface(name=name))
                iface.vlan = kv.get("vlan-id", "")
                iface.status = "down" if kv.get("disabled", "no") == "yes" else "up"
                vlans.append(
                    Vlan(
                        vlan_id=kv.get("vlan-id", ""),
                        name=name,
                        interfaces=[kv.get("interface", "")],
                    )
                )

            elif cur_section == "ip address" and "address" in kv:
                ifname = kv.get("interface", "")
                iface = iface_by_name.setdefault(ifname, Interface(name=ifname))
                ip, prefix = _split_address(kv["address"])
                iface.ip_address = ip
                iface.netmask = prefix
                iface.is_public = is_public_ip(ip)

            elif cur_section == "ip route":
                routes.append(
                    Route(
                        destination=kv.get("dst-address", "0.0.0.0/0"),
                        next_hop=kv.get("gateway", ""),
                        interface=(
                            kv.get("gateway", "")
                            if "interface" not in kv
                            else kv.get("interface", "")
                        ),
                    )
                )

            elif cur_section == "ip firewall filter":
                raw_action = kv.get("action", "")
                acl_rules.append(
                    AclRule(
                        action=_ACTION_MAP.get(raw_action, raw_action or "unknown"),
                        protocol=kv.get("protocol", "any"),
                        source=kv.get("src-address", "any"),
                        destination=kv.get("dst-address", "any"),
                        destination_port=kv.get("dst-port", ""),
                        interface=kv.get("in-interface", kv.get("out-interface", "")),
                        direction=kv.get("chain", ""),
                        raw=stripped,
                    )
                )

            elif cur_section == "ip firewall nat":
                has_static = "to-addresses" in kv
                nat_rules.append(
                    NatRule(
                        kind="static" if has_static else "dynamic",
                        inside_address=kv.get("to-addresses", kv.get("src-address", "")),
                        outside_address=kv.get("dst-address", ""),
                        inside_port=kv.get("to-ports", ""),
                        outside_port=kv.get("dst-port", ""),
                        raw=stripped,
                    )
                )

            elif cur_section == "system identity" and "name" in kv:
                system.hostname = kv["name"]

            elif cur_section == "user" or cur_section == "user group":
                if "name" in kv:
                    local_users.append(LocalUser(username=kv["name"], recoverable_secret=None))

        return ParsedConfig(
            vendor="mikrotik",
            system=system,
            interfaces=list(iface_by_name.values()),
            routes=routes,
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=vlans,
            object_groups=[],
            local_users=local_users,
            arp_entries=_parse_arp_table(raw_config),
            dhcp_leases=_parse_dhcp_leases(raw_config),
        )
