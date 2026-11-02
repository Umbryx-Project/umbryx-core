"""
Vendor-neutral intermediate representation for parsed firewall/router configs.

Every vendor parser (cisco_ios.py, mikrotik.py, ...) converts its native
syntax into a ParsedConfig. Enrichment (core/firewall_enrich.py) and diffing
(core/firewall_config_diff.py) only ever see this structure — they never
know which vendor a config came from. This is the stable contract between
the two layers: changing a field here requires updating both sides.

Object-group / named-address-group expansion (e.g. Cisco object-groups)
happens inside the vendor parser before AclRule/NatRule are constructed, so
`source`/`destination` here are always concrete addresses or "any" — never
an opaque group name.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Interface:
    name: str
    ip_address: str = ""
    netmask: str = ""
    vlan: str = ""
    status: str = ""  # "up" | "down" | "" (unknown — not all vendors report it)
    description: str = ""
    zone: str = (
        ""  # logical zone/nameif, e.g. ASA "outside"/"inside" — "" where a vendor has no concept of it
    )
    # True when ip_address is a publicly-routable address (see
    # firewall_parsers/util.py::is_public_ip). Computed once, by the vendor
    # parser, from the resolved concrete IP — never from an object-group
    # name. Real internet-facing attack surface vs. internal inventory;
    # enrichment (core/firewall_enrich.py) treats the two differently.
    is_public: bool = False


@dataclass
class Route:
    destination: str
    next_hop: str = ""
    interface: str = ""


@dataclass
class AclRule:
    action: str  # "permit" | "deny"
    protocol: str = "ip"
    source: str = "any"
    destination: str = "any"
    source_port: str = ""
    destination_port: str = ""
    interface: str = ""
    direction: str = ""  # "in" | "out" | ""
    raw: str = ""  # original line, for findings evidence/proof text


@dataclass
class NatRule:
    kind: str = "static"  # "static" | "dynamic"
    inside_address: str = ""
    outside_address: str = ""
    inside_port: str = ""
    outside_port: str = ""
    raw: str = ""


@dataclass
class Vlan:
    vlan_id: str
    name: str = ""
    interfaces: list[str] = field(default_factory=list)


@dataclass
class ObjectGroup:
    name: str
    kind: str = "network"  # "network" | "service"
    members: list[str] = field(default_factory=list)


@dataclass
class LocalUser:
    username: str
    # Only populated when the vendor's own encoding is trivially/statically
    # reversible (e.g. Cisco type 7) — never a real hash. None means either
    # no password was present or it's a one-way hash we don't attempt to
    # crack. Enrichment never persists this field verbatim outside the
    # encrypted Credentials store (see core/firewall_enrich.py).
    recoverable_secret: str | None = None


@dataclass
class ArpEntry:
    """One row of a device's ARP table — not config, *observed* live state
    at the time the operator ran the export command. Lets enrichment
    discover/confirm hosts that were never directly scanned."""

    ip: str
    mac: str
    interface: str = ""


@dataclass
class DhcpLease:
    """One row of a DHCP server's lease/binding table — same live-state
    caveat as ArpEntry, plus (when the vendor reports it) the client's
    self-announced hostname, which is often the single richest piece of
    identifying data available for a host that was never scanned."""

    ip: str
    mac: str
    hostname: str = ""


@dataclass
class SystemInfo:
    hostname: str = ""
    os_version: str = ""
    model: str = ""


@dataclass
class ParsedConfig:
    vendor: str
    system: SystemInfo = field(default_factory=SystemInfo)
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    acl_rules: list[AclRule] = field(default_factory=list)
    nat_rules: list[NatRule] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    object_groups: list[ObjectGroup] = field(default_factory=list)
    local_users: list[LocalUser] = field(default_factory=list)
    # Observed live state, not config — see ArpEntry/DhcpLease docstrings.
    # Only populated when the operator pasted the matching command's
    # output into the same upload as the config; empty otherwise.
    arp_entries: list[ArpEntry] = field(default_factory=list)
    dhcp_leases: list[DhcpLease] = field(default_factory=list)


@dataclass
class VendorInfo:
    vendor_key: str
    display_name: str
    supported_versions: str = ""
    notes: str = ""
