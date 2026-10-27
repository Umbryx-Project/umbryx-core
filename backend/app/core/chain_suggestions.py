"""
Scan chain suggestions — analyses scan results and proposes follow-up actions.

After a scan completes, this module inspects the results and returns
actionable "next step" suggestions that the operator can launch with
one click (e.g. nmap found web ports → suggest nuclei/httpx on those hosts).
"""

from __future__ import annotations

from .. import models

_WEB_PORTS = {80, 443, 8080, 8000, 8008, 8443, 4443, 3000, 5000, 9000}
_SMB_PORTS = {445}
_RDP_PORTS = {3389}
_SSH_PORTS = {22}
_WINRM_PORTS = {5985, 5986}
_MSSQL_PORTS = {1433}
_AD_PORTS = {88, 389, 636, 3268, 3269}


def parse_ports(ports: list[str]) -> set[int]:
    """Parse ['80/tcp', '443/tcp'] → {80, 443}."""
    result = set()
    for p in ports or []:
        try:
            result.add(int(str(p).split("/")[0]))
        except (ValueError, TypeError):
            pass
    return result


def suggest_chain_actions(
    db,
    pid: str,
    job: models.Job | None = None,
    hosts: list[models.Host] | None = None,
) -> list[dict]:
    """Return suggested next-step actions based on scan results or host data.

    Each suggestion is a dict:
      {id, label, connector, operation, target, description, icon}
    """
    suggestions: list[dict] = []

    # Gather hosts to analyse
    if hosts is None:
        q = db.query(models.Host).filter(
            models.Host.pid == pid,
            models.Host.deleted_at.is_(None),
        )
        if job and job.connector_key == "nmap":
            # Limit to hosts found by this scan (by target IP matching)
            import ipaddress

            target = (job.request_json or {}).get("target", "")
            if target:
                try:
                    net = ipaddress.ip_network(target, strict=False)
                    all_hosts = q.all()
                    hosts = [h for h in all_hosts if _ip_in_network(h.ip, net)]
                except ValueError:
                    hosts = q.filter(models.Host.ip == target).all()
            else:
                hosts = q.limit(100).all()
        else:
            hosts = q.limit(100).all()

    # Collect port info
    all_ports: set[int] = set()
    web_hosts: list[str] = []
    smb_hosts: list[str] = []
    rdp_hosts: list[str] = []
    ssh_hosts: list[str] = []
    winrm_hosts: list[str] = []
    ad_hosts: list[str] = []

    for h in hosts:
        host_ports = parse_ports(h.ports or [])
        all_ports |= host_ports
        if host_ports & _WEB_PORTS:
            web_hosts.append(h.ip)
        if host_ports & _SMB_PORTS:
            smb_hosts.append(h.ip)
        if host_ports & _RDP_PORTS:
            rdp_hosts.append(h.ip)
        if host_ports & _SSH_PORTS:
            ssh_hosts.append(h.ip)
        if host_ports & _WINRM_PORTS:
            winrm_hosts.append(h.ip)
        if host_ports & _AD_PORTS:
            ad_hosts.append(h.ip)

    # Web ports → suggest nuclei
    if web_hosts:
        target = ",".join(web_hosts[:20])
        suggestions.append(
            {
                "id": "nuclei-web",
                "label": f"Run Nuclei on {len(web_hosts)} web host(s)",
                "connector": "nuclei",
                "operation": "scan",
                "target": target,
                "description": f"Detected web ports on {len(web_hosts)} hosts — run vulnerability templates",
                "icon": "bug",
                "priority": "high",
            }
        )
        suggestions.append(
            {
                "id": "httpx-web",
                "label": f"Probe with httpx ({len(web_hosts)} host(s))",
                "connector": "httpx",
                "operation": "scan",
                "target": target,
                "description": "Get HTTP banners, titles, and tech stack for web hosts",
                "icon": "globe",
                "priority": "medium",
            }
        )

    # SMB ports → suggest netexec
    if smb_hosts:
        target = ",".join(smb_hosts[:20])
        suggestions.append(
            {
                "id": "cme-smb",
                "label": f"NetExec SMB on {len(smb_hosts)} host(s)",
                "connector": "netexec",
                "operation": "scan",
                "target": target,
                "description": f"SMB port open on {len(smb_hosts)} hosts — enumerate shares, users, sessions",
                "icon": "hosts",
                "priority": "high",
            }
        )

    # AD ports → suggest AD enumeration
    if ad_hosts:
        target = ",".join(ad_hosts[:5])
        suggestions.append(
            {
                "id": "cme-ad",
                "label": f"AD enumeration on {len(ad_hosts)} host(s)",
                "connector": "netexec",
                "operation": "scan",
                "target": target,
                "description": f"Active Directory ports detected on {len(ad_hosts)} hosts — full AD enum recommended",
                "icon": "shield",
                "priority": "high",
            }
        )

    # WinRM → suggest winrm auth check
    if winrm_hosts:
        target = ",".join(winrm_hosts[:10])
        suggestions.append(
            {
                "id": "winrm-check",
                "label": f"WinRM check on {len(winrm_hosts)} host(s)",
                "connector": "netexec",
                "operation": "scan",
                "target": target,
                "description": "WinRM ports open — test credential validity",
                "icon": "key",
                "priority": "medium",
            }
        )

    return suggestions


def _ip_in_network(ip: str, network) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip) in network
    except (ValueError, TypeError):
        return False
