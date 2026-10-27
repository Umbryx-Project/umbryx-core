"""
UniFi (USG/UDM) `config.gateway.json` parser.

Not line-based: USG/UDM config backups are JSON, an EdgeOS/Vyatta-derived
tree, not CLI text. detect() parses with the stdlib json module inside a
try/except so it returns False fast (never raises) on non-JSON input,
which means it never shadows the line-based vendors when the registry
probes every parser in turn.

This export never contains local admin passwords — recoverable_secret is
always None.
"""

from __future__ import annotations

import json

from .base import FirewallConfigParser, FirewallParserRegistry
from .schema import (
    AclRule,
    Interface,
    NatRule,
    ParsedConfig,
    Route,
    SystemInfo,
    VendorInfo,
    Vlan,
)
from .util import is_public_ip

_ACTION_MAP = {"accept": "permit", "drop": "deny", "reject": "deny"}


def _try_load(raw_config: str) -> dict | None:
    try:
        data = json.loads(raw_config)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


@FirewallParserRegistry.register("unifi")
class UniFiParser(FirewallConfigParser):
    def detect(self, raw_config: str) -> bool:
        data = _try_load(raw_config)
        if data is None:
            return False
        return "interfaces" in data or "firewall" in data

    def get_vendor_info(self) -> VendorInfo:
        return VendorInfo(
            vendor_key="unifi",
            display_name="UniFi (EdgeOS/USG)",
            supported_versions="USG/UDM `config.gateway.json` backup export",
            notes="No local admin passwords are present in this export.",
        )

    def parse(self, raw_config: str) -> ParsedConfig:
        data = _try_load(raw_config) or {}
        system = SystemInfo(hostname=str(data.get("system", {}).get("host-name", "") or ""))
        interfaces: list[Interface] = []
        routes: list[Route] = []
        acl_rules: list[AclRule] = []
        nat_rules: list[NatRule] = []
        vlans: list[Vlan] = []

        eth = data.get("interfaces", {}).get("ethernet", {}) or {}
        for name, cfg in eth.items():
            if not isinstance(cfg, dict):
                continue
            addrs = cfg.get("address", [])
            if isinstance(addrs, str):
                addrs = [addrs]
            ip, netmask = "", ""
            if addrs:
                ip, _, netmask = str(addrs[0]).partition("/")
            interfaces.append(
                Interface(
                    name=str(name),
                    ip_address=ip,
                    netmask=netmask,
                    description=str(cfg.get("description", "") or ""),
                    is_public=is_public_ip(ip),
                )
            )

        switches = data.get("interfaces", {}).get("switch", {}) or {}
        for sw_name, sw_cfg in switches.items():
            if not isinstance(sw_cfg, dict):
                continue
            for vlan_id, vif_cfg in (sw_cfg.get("vif", {}) or {}).items():
                if not isinstance(vif_cfg, dict):
                    continue
                addrs = vif_cfg.get("address", [])
                if isinstance(addrs, str):
                    addrs = [addrs]
                ip, netmask = ("", "")
                if addrs:
                    ip, _, netmask = str(addrs[0]).partition("/")
                iface_name = f"{sw_name}.{vlan_id}"
                interfaces.append(
                    Interface(
                        name=iface_name,
                        ip_address=ip,
                        netmask=netmask,
                        vlan=str(vlan_id),
                        is_public=is_public_ip(ip),
                    )
                )
                vlans.append(Vlan(vlan_id=str(vlan_id), interfaces=[str(sw_name)]))

        static = data.get("protocols", {}).get("static", {}).get("route", {}) or {}
        for dest, route_cfg in static.items():
            if not isinstance(route_cfg, dict):
                continue
            next_hops = list((route_cfg.get("next-hop", {}) or {}).keys())
            routes.append(
                Route(destination=str(dest), next_hop=str(next_hops[0]) if next_hops else "")
            )

        rulesets = data.get("firewall", {}).get("name", {}) or {}
        for ruleset_name, ruleset_cfg in rulesets.items():
            if not isinstance(ruleset_cfg, dict):
                continue
            for _rule_num, rule in (ruleset_cfg.get("rule", {}) or {}).items():
                if not isinstance(rule, dict):
                    continue
                action = str(rule.get("action", "") or "").lower()
                src = (rule.get("source", {}) or {}).get("address", "any")
                dst = (rule.get("destination", {}) or {}).get("address", "any")
                dport = (rule.get("destination", {}) or {}).get("port", "")
                acl_rules.append(
                    AclRule(
                        action=_ACTION_MAP.get(action, action or "unknown"),
                        protocol=str(rule.get("protocol", "any") or "any"),
                        source=str(src or "any"),
                        destination=str(dst or "any"),
                        destination_port=str(dport or ""),
                        raw=f"{ruleset_name}: {action}",
                    )
                )

        nat_rules_raw = data.get("service", {}).get("nat", {}).get("rule", {}) or {}
        for _rule_num, rule in nat_rules_raw.items():
            if not isinstance(rule, dict):
                continue
            inside = (rule.get("inside-address", {}) or {}).get("address", "")
            outside = (rule.get("outside-address", {}) or {}).get("address", "")
            nat_rules.append(
                NatRule(
                    kind="static" if inside and outside else "dynamic",
                    inside_address=str(inside or ""),
                    outside_address=str(outside or ""),
                    raw=str(rule.get("type", "")),
                )
            )

        return ParsedConfig(
            vendor="unifi",
            system=system,
            interfaces=interfaces,
            routes=routes,
            acl_rules=acl_rules,
            nat_rules=nat_rules,
            vlans=vlans,
            object_groups=[],
            local_users=[],
        )
