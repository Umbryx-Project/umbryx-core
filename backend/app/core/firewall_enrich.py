"""
Turns a vendor-neutral ParsedConfig into platform objects — Host (the
device), Scope entries (discovered subnets), Findings (config-analysis
only, no CVE matching — see docs), and Credentials (recoverable local
passwords).

Follows the same upsert-by-natural-key idempotency style as
core/scan_helpers.py (nmap_upsert_host, ffuf_upsert_finding,
donpapi_upsert_cred) so re-applying the same/updated config never creates
duplicates.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from dataclasses import dataclass

from .. import models
from .firewall_parsers.schema import LocalUser, ParsedConfig
from .key_management import encrypt_for_project
from .utils import new_id, ts_now

_ANY_VALUES = {"any", "0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0", ""}
_ADMIN_PORTS = {
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "80": "HTTP admin",
    "161": "SNMP",
    "3389": "RDP",
    "8080": "HTTP admin",
    "8291": "MikroTik Winbox",
}


@dataclass
class FirewallEnrichResult:
    host_created: bool
    host_id: str | None
    networks_created: int
    networks_existing: int
    findings_created: int
    findings_skipped: int
    creds_created: int
    creds_skipped: int
    hosts_discovered: int
    hosts_enriched: int


def parsed_config_to_safe_dict(parsed: ParsedConfig) -> dict:
    """dataclasses.asdict(parsed) with recoverable secrets stripped — this
    is what gets persisted in FirewallConfigUpload.parsed_json and returned
    from the preview/history API. Secrets only ever reach the encrypted
    Cred store (see _upsert_local_user_cred)."""
    d = dataclasses.asdict(parsed)
    for user in d.get("local_users", []):
        user["recoverable_secret"] = None
    return d


def _is_any(value: str) -> bool:
    return (value or "").strip().lower() in _ANY_VALUES


def _port_num(port_field: str) -> str:
    parts = (port_field or "").split()
    return parts[-1] if parts else ""


def _analyze_acl_findings(
    vendor: str, acl_rules: list, nat_rules: list
) -> list[tuple[str, str, str, str]]:
    """Pure config-analysis findings (permit-any-any, exposed admin
    services). No CVE/version matching — no such mechanism exists in this
    codebase (confirmed during design); that would be a separate project.
    Returns (title, severity, description, proof) tuples."""
    findings: list[tuple[str, str, str, str]] = []
    seen_titles: set[str] = set()

    for rule in acl_rules:
        if getattr(rule, "action", "") != "permit":
            continue
        src, dst = getattr(rule, "source", ""), getattr(rule, "destination", "")
        protocol = (getattr(rule, "protocol", "") or "").lower()
        port = _port_num(getattr(rule, "destination_port", ""))

        if _is_any(src) and _is_any(dst) and not port and protocol in ("ip", "any", "0", ""):
            title = "Firewall ACL: unrestricted permit any/any"
            if title not in seen_titles:
                seen_titles.add(title)
                findings.append(
                    (
                        title,
                        "high",
                        f"A rule permits all traffic from any source to any destination with no "
                        f"protocol/port restriction ({vendor}).",
                        getattr(rule, "raw", ""),
                    )
                )
        elif _is_any(src) and port in _ADMIN_PORTS:
            svc = _ADMIN_PORTS[port]
            title = f"Firewall ACL: {svc} reachable from any source"
            if title not in seen_titles:
                seen_titles.add(title)
                findings.append(
                    (
                        title,
                        "medium",
                        f"A rule permits {svc} (port {port}/{protocol or 'tcp'}) to {dst} from any "
                        f"source ({vendor}).",
                        getattr(rule, "raw", ""),
                    )
                )

    for rule in nat_rules:
        oport = _port_num(getattr(rule, "outside_port", ""))
        if oport in _ADMIN_PORTS:
            svc = _ADMIN_PORTS[oport]
            title = f"Firewall NAT: {svc} exposed externally"
            if title not in seen_titles:
                seen_titles.add(title)
                findings.append(
                    (
                        title,
                        "medium",
                        f"A NAT rule maps external port {oport} ({svc}) to an internal address "
                        f"({vendor}).",
                        getattr(rule, "raw", ""),
                    )
                )

    return findings


def _iface_to_cidr(iface) -> str | None:
    if not iface.ip_address or not iface.netmask:
        return None
    try:
        network = ipaddress.ip_network(f"{iface.ip_address}/{iface.netmask}", strict=False)
        return str(network)
    except ValueError:
        return None


def _resolve_device_host(db, pid: str, parsed: ParsedConfig, vendor: str):
    device_ip = next((i.ip_address for i in parsed.interfaces if i.ip_address), "")
    hostname = parsed.system.hostname

    existing = None
    if device_ip:
        existing = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.ip == device_ip)
            .first()
        )
    if not existing and hostname:
        existing = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.hostname == hostname)
            .first()
        )

    extra_tags = ["firewall", vendor]
    if any(i.is_public for i in parsed.interfaces):
        extra_tags.append("external-facing")

    if existing:
        if hostname and not existing.hostname:
            existing.hostname = hostname
        if parsed.system.os_version and not existing.os:
            existing.os = f"{vendor} {parsed.system.os_version}".strip()
        existing.status = "up"
        existing.tags = list(set((existing.tags or []) + extra_tags))
        if not existing.import_source:
            existing.import_source = vendor
        return existing, False

    if not device_ip and not hostname:
        # Nothing to key a Host on — still enrich networks/findings/creds,
        # just leave them unassociated with a specific device Host.
        return None, False

    host_obj = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=device_ip or "",
        hostname=hostname or "",
        os=f"{vendor} {parsed.system.os_version}".strip(),
        status="up",
        tags=extra_tags,
        role="firewall",
        import_source=vendor,
    )
    db.add(host_obj)
    return host_obj, True


def _upsert_scope_network(
    db, pid: str, cidr: str, vendor: str, iface_name: str, is_public: bool
) -> bool:
    existing = (
        db.query(models.Scope)
        .filter(
            models.Scope.pid == pid, models.Scope.value == cidr, models.Scope.scope_type == "cidr"
        )
        .first()
    )
    if existing:
        return False
    # A public IP on an interface is real internet-facing attack surface —
    # surface it immediately (in_scope=True) rather than requiring the
    # operator to notice and manually promote it. Private ranges keep the
    # previous default (discovered, not yet confirmed in scope).
    marker = "external" if is_public else "internal"
    db.add(
        models.Scope(
            id=new_id("scp"),
            pid=pid,
            value=cidr,
            scope_type="cidr",
            in_scope=is_public,
            description=f"Discovered via {vendor} config (interface {iface_name}, {marker})",
        )
    )
    return True


def _upsert_firewall_finding(
    db, pid: str, host_obj, title: str, severity: str, description: str, proof: str
) -> bool:
    existing = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.title == title)
        .first()
    )
    if existing:
        return False
    db.add(
        models.Finding(
            id=new_id("fnd"),
            pid=pid,
            host_id=host_obj.id if host_obj else None,
            title=title,
            severity=severity,
            description=description,
            proof=proof,
            status="open",
            source="firewall_config",
            ts=ts_now(),
        )
    )
    return True


def _upsert_local_user_cred(db, pid: str, user: LocalUser, vendor: str, host_obj) -> bool:
    if not user.recoverable_secret:
        return False
    host_ip = host_obj.ip if host_obj else ""
    existing = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == user.username,
            models.Cred.service == "firewall_config",
            models.Cred.host == host_ip,
        )
        .first()
    )
    if existing:
        return False
    db.add(
        models.Cred(
            id=new_id("crd"),
            pid=pid,
            username=user.username,
            secret=encrypt_for_project(db, pid, user.recoverable_secret),
            type="plain",
            service="firewall_config",
            host=host_ip,
            host_ids=[host_obj.id] if host_obj else [],
            tags=["firewall-config", vendor],
        )
    )
    return True


def _upsert_arp_dhcp_hosts(db, pid: str, parsed: ParsedConfig, vendor: str) -> tuple[int, int]:
    """ARP/DHCP entries are *observed* live state, not config — when the
    operator pastes `show arp`/DHCP-lease command output into the same
    upload, every distinct IP either enriches an already-known Host (adds
    a `mac:...` tag, fills in hostname if still blank) or creates a
    lightweight stub Host, so a device shows up in recon even though it
    was never directly scanned. Returns (hosts_discovered, hosts_enriched).
    """
    by_ip: dict[str, dict] = {}
    for entry in parsed.arp_entries:
        by_ip.setdefault(entry.ip, {})["mac"] = entry.mac
    for lease in parsed.dhcp_leases:
        row = by_ip.setdefault(lease.ip, {})
        row.setdefault("mac", lease.mac)
        if lease.hostname:
            row["hostname"] = lease.hostname

    discovered = enriched = 0
    for ip, info in by_ip.items():
        mac = info.get("mac", "")
        mac_tag = f"mac:{mac}" if mac else None
        existing = (
            db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
        )
        if existing:
            changed = False
            if mac_tag and mac_tag not in (existing.tags or []):
                existing.tags = list({*(existing.tags or []), mac_tag})
                changed = True
            if info.get("hostname") and not existing.hostname:
                existing.hostname = info["hostname"]
                changed = True
            if changed:
                enriched += 1
            continue
        tags = ["discovered-via-arp-dhcp", vendor]
        if mac_tag:
            tags.append(mac_tag)
        db.add(
            models.Host(
                id=new_id("hst"),
                pid=pid,
                ip=ip,
                hostname=info.get("hostname", ""),
                status="unknown",
                tags=tags,
                import_source=vendor,
            )
        )
        discovered += 1
    return discovered, enriched


def enrich_project_from_config(
    db, pid: str, parsed: ParsedConfig, vendor: str
) -> FirewallEnrichResult:
    host_obj, host_created = _resolve_device_host(db, pid, parsed, vendor)
    # Flush now: Finding.host_id has a DB-level FK to hosts.id (not declared
    # on the SQLAlchemy model, only in the migration-built schema — so a
    # sqlite/model-only test schema won't catch this, but real Postgres
    # will reject a Finding insert that races ahead of a still-pending Host
    # insert in the same autoflush batch). Confirmed against the live
    # Postgres stack during development.
    if host_obj is not None and host_created:
        db.flush()

    networks_created = networks_existing = 0
    for iface in parsed.interfaces:
        cidr = _iface_to_cidr(iface)
        if not cidr:
            continue
        if _upsert_scope_network(db, pid, cidr, vendor, iface.name, iface.is_public):
            networks_created += 1
        else:
            networks_existing += 1

    findings_created = findings_skipped = 0
    for title, severity, description, proof in _analyze_acl_findings(
        vendor, parsed.acl_rules, parsed.nat_rules
    ):
        if _upsert_firewall_finding(db, pid, host_obj, title, severity, description, proof):
            findings_created += 1
        else:
            findings_skipped += 1

    creds_created = creds_skipped = 0
    for user in parsed.local_users:
        if not user.recoverable_secret:
            continue
        if _upsert_local_user_cred(db, pid, user, vendor, host_obj):
            creds_created += 1
        else:
            creds_skipped += 1

    hosts_discovered, hosts_enriched = _upsert_arp_dhcp_hosts(db, pid, parsed, vendor)

    return FirewallEnrichResult(
        host_created=host_created,
        host_id=host_obj.id if host_obj else None,
        networks_created=networks_created,
        networks_existing=networks_existing,
        findings_created=findings_created,
        findings_skipped=findings_skipped,
        creds_created=creds_created,
        creds_skipped=creds_skipped,
        hosts_discovered=hosts_discovered,
        hosts_enriched=hosts_enriched,
    )
