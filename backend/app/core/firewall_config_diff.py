"""
Diff between two parsed firewall config snapshots (dict form of ParsedConfig,
as stored in FirewallConfigUpload.parsed_json), for the same device.

Mirrors core/scan_diff.py::diff_snapshots — same "added/removed" shape,
computed on demand from the two most recent stored snapshots rather than
persisted separately.
"""

from __future__ import annotations


def _index(items: list[dict], keys: tuple[str, ...]) -> dict[tuple, dict]:
    return {tuple(item.get(k, "") for k in keys): item for item in items}


_INTERFACE_KEYS = ("name", "ip_address", "netmask", "vlan", "status", "is_public")
_ROUTE_KEYS = ("destination", "next_hop", "interface")
_ACL_KEYS = ("action", "protocol", "source", "destination", "destination_port")
_NAT_KEYS = ("kind", "inside_address", "outside_address", "inside_port", "outside_port")


def _diff_list(
    old_items: list[dict], new_items: list[dict], keys: tuple[str, ...]
) -> tuple[list[dict], list[dict]]:
    old_idx = _index(old_items or [], keys)
    new_idx = _index(new_items or [], keys)
    added = [v for k, v in new_idx.items() if k not in old_idx]
    removed = [v for k, v in old_idx.items() if k not in new_idx]
    return added, removed


def diff_parsed_configs(old: dict, new: dict) -> dict:
    """old/new are dict-serialized ParsedConfig (e.g. dataclasses.asdict()).
    Either may be {} (no previous upload) — everything in `new` is then
    reported as added.
    """
    added_ifaces, removed_ifaces = _diff_list(
        old.get("interfaces", []), new.get("interfaces", []), _INTERFACE_KEYS
    )
    added_routes, removed_routes = _diff_list(
        old.get("routes", []), new.get("routes", []), _ROUTE_KEYS
    )
    added_acl, removed_acl = _diff_list(
        old.get("acl_rules", []), new.get("acl_rules", []), _ACL_KEYS
    )
    added_nat, removed_nat = _diff_list(
        old.get("nat_rules", []), new.get("nat_rules", []), _NAT_KEYS
    )

    old_system = old.get("system", {}) or {}
    new_system = new.get("system", {}) or {}
    hostname_changed = old_system.get("hostname", "") != new_system.get("hostname", "")
    os_version_changed = old_system.get("os_version", "") != new_system.get("os_version", "")

    has_changes = bool(
        added_ifaces
        or removed_ifaces
        or added_routes
        or removed_routes
        or added_acl
        or removed_acl
        or added_nat
        or removed_nat
        or hostname_changed
        or os_version_changed
    )

    return {
        "added_interfaces": added_ifaces,
        "removed_interfaces": removed_ifaces,
        "added_routes": added_routes,
        "removed_routes": removed_routes,
        "added_acl_rules": added_acl,
        "removed_acl_rules": removed_acl,
        "added_nat_rules": added_nat,
        "removed_nat_rules": removed_nat,
        "hostname_changed": hostname_changed,
        "os_version_changed": os_version_changed,
        "has_changes": has_changes,
    }
