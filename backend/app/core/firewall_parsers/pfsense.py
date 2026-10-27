"""
pfSense `config.xml` parser.

Not line-based: pfSense exports its full config as XML. detect() parses
with the stdlib xml.etree.ElementTree module — deliberately not lxml,
since ElementTree (backed by expat) does not resolve *external* entities
or fetch external DTDs by default, closing the XXE data-exfiltration
angle for a config file an operator uploads from an untrusted/unverified
source. That alone doesn't rule out *internal* entity expansion
("billion laughs") DoS, so _try_parse additionally rejects any input
containing a DOCTYPE/ENTITY declaration outright before it ever reaches
the parser — a real pfSense config.xml export never contains one, so this
is a pure allow-list, not a bypassable blocklist. Malformed/adversarial
XML raises ParseError, caught here and treated as "not this vendor"
(detect) or an empty result (parse), same as the other parsers'
malformed-input handling.

Local user secrets in config.xml are bcrypt hashes — never recoverable.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .base import FirewallConfigParser, FirewallParserRegistry
from .schema import (
    AclRule,
    Interface,
    LocalUser,
    NatRule,
    ParsedConfig,
    Route,
    SystemInfo,
    VendorInfo,
    Vlan,
)
from .util import is_public_ip

_WAN_LAN_OPT_NAMES = ("wan", "lan")


def _try_parse(raw_config: str) -> ET.Element | None:
    lowered = raw_config.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return None
    try:
        return ET.fromstring(raw_config)
    except ET.ParseError:
        return None


def _text(el: ET.Element | None, tag: str) -> str:
    if el is None:
        return ""
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


@FirewallParserRegistry.register("pfsense")
class PfSenseParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        root = _try_parse(raw_config)
        if root is None:
            return False
        return (
            root.tag == "pfsense"
            or root.find("filter") is not None
            or root.find("interfaces") is not None
        )

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="pfsense",
            display_name="pfSense",
            supported_versions="pfSense 2.x `config.xml` export",
            notes="Local user secrets are bcrypt hashes — never recoverable.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        root = _try_parse(raw_config)
        if root is None:
            return ParsedConfig(vendor="pfsense")

        system = SystemInfo(hostname=_text(root.find("system"), "hostname"))
        interfaces: list[Interface] = []
        routes: list[Route] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        vlans: list[Vlan] = []
        local_users: list[LocalUser] = []

        ifaces_el = root.find("interfaces")
        if ifaces_el is not None:
            for iface_el in ifaces_el:
                ip = _text(iface_el, "ipaddr")
                if not ip or ip in ("dhcp", "pppoe", "none"):
                    interfaces.append(
                        Interface(
                            name=iface_el.tag,
                            status="up" if _text(iface_el, "enable") != "" else "",
                        )
                    )
                    continue
                interfaces.append(
                    Interface(
                        name=iface_el.tag,
                        ip_address=ip,
                        netmask=_text(iface_el, "subnet"),
                        description=_text(iface_el, "descr"),
                        status="up",
                        is_public=is_public_ip(ip),
                    )
                )

        static_routes_el = root.find("staticroutes")
        if static_routes_el is not None:
            for route_el in static_routes_el.findall("route"):
                routes.append(
                    Route(
                        destination=_text(route_el, "network"), next_hop=_text(route_el, "gateway")
                    )
                )

        filter_el = root.find("filter")
        if filter_el is not None:
            for rule_el in filter_el.findall("rule"):
                rule_type = _text(rule_el, "type") or "block"
                src_el = rule_el.find("source")
                dst_el = rule_el.find("destination")
                source = (
                    "any"
                    if src_el is not None and src_el.find("any") is not None
                    else _text(src_el, "address") or "any"
                )
                dest = (
                    "any"
                    if dst_el is not None and dst_el.find("any") is not None
                    else _text(dst_el, "address") or "any"
                )
                dport = _text(dst_el, "port")
                acl_rules.append(
                    AclRule(
                        action="permit" if rule_type == "pass" else "deny",
                        protocol=_text(rule_el, "protocol") or "any",
                        source=source,
                        destination=dest,
                        destination_port=dport,
                        raw=f"{rule_type} {_text(rule_el, 'protocol')} {source}->{dest}",
                    )
                )

        nat_el = root.find("nat")
        if nat_el is not None:
            for rule_el in nat_el.findall("rule"):
                src_addr = _text(rule_el.find("source"), "address")
                dst_addr = _text(rule_el.find("destination"), "address")
                nat_rules.append(
                    NatRule(
                        kind="static" if src_addr and dst_addr else "dynamic",
                        inside_address=src_addr,
                        outside_address=dst_addr,
                        raw="nat rule",
                    )
                )

        vlans_el = root.find("vlans")
        if vlans_el is not None:
            for vlan_el in vlans_el.findall("vlan"):
                vlans.append(
                    Vlan(
                        vlan_id=_text(vlan_el, "tag"),
                        name=_text(vlan_el, "descr"),
                        interfaces=[_text(vlan_el, "if")] if _text(vlan_el, "if") else [],
                    )
                )

        system_el = root.find("system")
        if system_el is not None:
            for user_el in system_el.findall("user"):
                username = _text(user_el, "name")
                if username:
                    local_users.append(LocalUser(username=username, recoverable_secret=None))

        return ParsedConfig(
            vendor="pfsense",
            system=system,
            interfaces=interfaces,
            routes=routes,
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=vlans,
            object_groups=[],
            local_users=local_users,
        )
