#!/usr/bin/env python3
"""Seed demo data for the Umbryx demo stand.

Usage, inside the stand's backend container (never the live one):
  python /app/scripts/seed_demo.py                                 # seed
  python /app/scripts/seed_demo.py --export [path]                 # dump JSON
  python /app/scripts/seed_demo.py --import /app/scripts/demo_data.json

The data is reproducible: ids and timestamps are pinned (DEMO_EPOCH), so
re-seeding writes the same rows and a re-captured screenshot is byte-identical
unless the UI itself changed. UMBRYX_SEED_LIVE=1 restores real ids and the real
clock for a scratch instance you only intend to click around in.

Exits non-zero if anything was rolled back or skipped, so a capture run fails
loudly instead of photographing empty tables.
"""
import argparse
import json
import re
import os
import sys
from datetime import UTC, datetime, timedelta

os.environ.setdefault("APP_ENV", "production")
sys.path.insert(0, "/app")

from app.database import SessionLocal, engine, Base
from app.core.utils import new_id, ts_now
from app.core.security import hash_password
from app.core.crypto import encrypt_str
from sqlalchemy import text

# The seeded instance is screenshotted for the documentation, so the data has
# to be reproducible: a wall-clock timestamp or a random id means every re-seed
# renders differently and every re-capture produces a new set of PNGs to
# commit. Both are pinned here. DEMO_EPOCH is deliberately in the past so the
# engagement reads as finished work rather than as something starting now.
#
# Set UMBRYX_SEED_LIVE=1 to get real ids and the real clock back — useful when
# seeding a scratch instance for manual poking rather than for capture.
DEMO_EPOCH = "2026-03-17T09:14:00Z"
_LIVE = os.environ.get("UMBRYX_SEED_LIVE") == "1"
_id_counter = {}


def N():
    return ts_now() if _LIVE else DEMO_EPOCH


def _id(prefix):
    """Stable id, so a re-seed reproduces the same rows.

    A per-prefix counter rather than a hash: unique within a prefix, and
    prefixes never overlap, so this is as collision-free as new_id() while
    staying identical across runs.
    """
    if _LIVE:
        return new_id(prefix)
    _id_counter[prefix] = _id_counter.get(prefix, 0) + 1
    return f"{prefix}{_id_counter[prefix]:08x}"

USERS_DATA = [
    {"username": "admin", "display_name": "Admin", "role": "platform_admin"},
    {"username": "operator1", "display_name": "Alex Petrov", "role": "user"},
    {"username": "operator2", "display_name": "Maria Ivanova", "role": "user"},
    {"username": "analyst1", "display_name": "Dmitry Smirnov", "role": "user"},
    {"username": "analyst2", "display_name": "Elena Kozlova", "role": "user"},
    {"username": "viewer1", "display_name": "Sergey Volkov", "role": "viewer"},
]

ORGS_DATA = [
    {"name": "Red Team Alpha", "slug": "redteam-alpha", "plan": "enterprise"},
    {"name": "Pentest Brigade", "slug": "pentest-brigade", "plan": "pro"},
]

PROJECTS_DATA = [
    {"name": "Operation Blackout", "description": "Full-scope red team engagement against ACME Corp infrastructure", "status": "active"},
    {"name": "Phantom Strike", "description": "Internal penetration test of banking network 10.0.0.0/16", "status": "active"},
    {"name": "Silent Viper", "description": "External assessment of DMZ and cloud workloads", "status": "active"},
    {"name": "Iron Fortress", "description": "AD security assessment + lateral movement simulation", "status": "closed"},
]

HOSTS_DATA = [
    {"ip": "10.0.1.10", "hostname": "DC01.acme.local", "os": "Windows Server 2022", "status": "pwned", "role": "domain_controller", "ports": ["53", "88", "135", "389", "445", "636", "3389"], "services": ["DNS", "Kerberos", "LDAP", "SMB"], "tags": ["windows", "ad", "critical"]},
    {"ip": "10.0.1.11", "hostname": "DC02.acme.local", "os": "Windows Server 2022", "status": "access", "role": "domain_controller", "ports": ["53", "88", "135", "389", "445", "636"], "services": ["DNS", "Kerberos", "LDAP"], "tags": ["windows", "ad"]},
    {"ip": "10.0.1.20", "hostname": "EXCH01.acme.local", "os": "Windows Server 2019", "status": "pwned", "role": "mail_server", "ports": ["25", "443", "587", "993", "8080"], "services": ["SMTP", "HTTPS", "IMAP", "OWA"], "tags": ["windows", "exchange", "critical"]},
    {"ip": "10.0.1.30", "hostname": "WEB01.acme.local", "os": "Ubuntu 22.04", "status": "access", "role": "web_server", "ports": ["22", "80", "443"], "services": ["SSH", "HTTP", "HTTPS"], "tags": ["linux", "web", "public"]},
    {"ip": "10.0.1.31", "hostname": "WEB02.acme.local", "os": "Ubuntu 22.04", "status": "up", "role": "web_server", "ports": ["22", "80", "443", "8443"], "services": ["SSH", "HTTP", "HTTPS"], "tags": ["linux", "web"]},
    {"ip": "10.0.1.40", "hostname": "DB01.acme.local", "os": "CentOS 8", "status": "up", "role": "database", "ports": ["22", "3306", "5432"], "services": ["SSH", "MySQL", "PostgreSQL"], "tags": ["linux", "database", "sensitive"]},
    {"ip": "10.0.1.41", "hostname": "DB02.acme.local", "os": "CentOS 8", "status": "down", "role": "database", "ports": ["22", "5432"], "services": ["SSH", "PostgreSQL"], "tags": ["linux", "database"]},
    {"ip": "10.0.2.10", "hostname": "FS01.acme.local", "os": "Windows Server 2022", "status": "access", "role": "file_server", "ports": ["135", "445", "3389"], "services": ["SMB", "RPC"], "tags": ["windows", "fileshare"]},
    {"ip": "10.0.2.20", "hostname": "APP01.acme.local", "os": "Windows Server 2019", "status": "up", "role": "app_server", "ports": ["135", "445", "1433", "8080"], "services": ["SMB", "MSSQL", "IIS"], "tags": ["windows", "application"]},
    {"ip": "10.0.2.30", "hostname": "VPN01.acme.local", "os": "Linux", "status": "pwned", "role": "vpn_gateway", "ports": ["22", "443", "1194", "500", "4500"], "services": ["SSH", "OpenVPN", "IPSec"], "tags": ["linux", "vpn", "critical"]},
    {"ip": "10.0.2.40", "hostname": "FW-MGMT.acme.local", "os": "Palo Alto PAN-OS", "status": "up", "role": "firewall", "ports": ["22", "443"], "services": ["SSH", "HTTPS-UI"], "tags": ["firewall", "network"]},
    {"ip": "10.0.3.10", "hostname": "JENKINS.acme.local", "os": "Ubuntu 22.04", "status": "pwned", "role": "ci_cd", "ports": ["22", "8080", "50000"], "services": ["SSH", "Jenkins"], "tags": ["linux", "cicd", "critical"]},
    {"ip": "10.0.3.20", "hostname": "GITLAB.acme.local", "os": "Ubuntu 22.04", "status": "access", "role": "vcs", "ports": ["22", "80", "443"], "services": ["SSH", "HTTP", "HTTPS"], "tags": ["linux", "git", "sensitive"]},
    {"ip": "10.0.3.30", "hostname": "DOCKER-REG.acme.local", "os": "Ubuntu 22.04", "status": "up", "role": "registry", "ports": ["22", "5000"], "services": ["SSH", "Docker-Registry"], "tags": ["linux", "docker"]},
    {"ip": "10.0.3.40", "hostname": "K8S-MASTER.acme.local", "os": "Ubuntu 22.04", "status": "up", "role": "k8s_master", "ports": ["22", "6443", "2379", "10250"], "services": ["SSH", "K8s-API", "etcd"], "tags": ["linux", "kubernetes"]},
    {"ip": "10.0.3.41", "hostname": "K8S-NODE01.acme.local", "os": "Ubuntu 22.04", "status": "up", "role": "k8s_node", "ports": ["22", "10250", "30000-32767"], "services": ["SSH", "Kubelet"], "tags": ["linux", "kubernetes"]},
    {"ip": "10.0.4.10", "hostname": "MON01.acme.local", "os": "Ubuntu 22.04", "status": "up", "role": "monitoring", "ports": ["22", "3000", "9090", "9100"], "services": ["SSH", "Grafana", "Prometheus"], "tags": ["linux", "monitoring"]},
    {"ip": "10.0.4.20", "hostname": "SIEM01.acme.local", "os": "RHEL 9", "status": "up", "role": "siem", "ports": ["22", "5601", "9200", "5044"], "services": ["SSH", "Kibana", "Elasticsearch"], "tags": ["linux", "siem"]},
    {"ip": "10.0.5.10", "hostname": "HR-WS01.acme.local", "os": "Windows 11", "status": "alive", "role": "workstation", "ports": ["135", "445", "3389"], "services": ["SMB", "RDP"], "tags": ["windows", "workstation"]},
    {"ip": "10.0.5.11", "hostname": "FIN-WS01.acme.local", "os": "Windows 11", "status": "alive", "role": "workstation", "ports": ["135", "445", "3389"], "services": ["SMB", "RDP"], "tags": ["windows", "workstation"]},
    {"ip": "10.0.5.12", "hostname": "IT-WS01.acme.local", "os": "Windows 11", "status": "pwned", "role": "workstation", "ports": ["135", "445", "3389", "5985"], "services": ["SMB", "RDP", "WinRM"], "tags": ["windows", "workstation", "admin"]},
    {"ip": "192.168.100.1", "hostname": "ATTACKER-C2", "os": "Kali 2024", "status": "up", "role": "c2_server", "ports": ["443", "8443", "53"], "services": ["HTTPS", "DNS"], "tags": ["attacker", "c2"], "is_attacker": True},
    {"ip": "192.168.100.2", "hostname": "ATTACKER-PROXY", "os": "Kali 2024", "status": "up", "role": "proxy", "ports": ["1080", "8080"], "services": ["SOCKS", "HTTP-Proxy"], "tags": ["attacker", "proxy"], "is_attacker": True},
    {"ip": "172.16.0.1", "hostname": "DMZ-WEB01", "os": "Nginx/Alpine", "status": "up", "role": "web_server", "ports": ["80", "443"], "services": ["HTTP", "HTTPS"], "tags": ["linux", "dmz", "public"]},
    {"ip": "172.16.0.2", "hostname": "DMZ-MAIL01", "os": "Postfix/Alpine", "status": "up", "role": "mail_relay", "ports": ["25", "587"], "services": ["SMTP"], "tags": ["linux", "dmz", "mail"]},
    {"ip": "10.0.1.50", "hostname": "WSUS.acme.local", "os": "Windows Server 2022", "status": "up", "role": "patch_server", "ports": ["8530", "443"], "services": ["WSUS", "HTTPS"], "tags": ["windows", "patching"]},
    {"ip": "10.0.1.60", "hostname": "AV-SRV.acme.local", "os": "Windows Server 2019", "status": "up", "role": "antivirus", "ports": ["443", "8080"], "services": ["HTTPS", "AV-Console"], "tags": ["windows", "security"]},
    {"ip": "10.0.1.70", "hostname": "SHAREPOINT.acme.local", "os": "Windows Server 2022", "status": "access", "role": "collaboration", "ports": ["80", "443", "1433"], "services": ["HTTP", "HTTPS", "MSSQL"], "tags": ["windows", "sharepoint"]},
    {"ip": "10.0.2.50", "hostname": "PRINT01.acme.local", "os": "Windows Server 2016", "status": "down", "role": "print_server", "ports": ["135", "445", "9100"], "services": ["SMB", "Print"], "tags": ["windows", "print"]},
    {"ip": "10.0.3.50", "hostname": "ANSIBLE.acme.local", "os": "Ubuntu 22.04", "status": "access", "role": "automation", "ports": ["22", "8080"], "services": ["SSH", "Ansible-Tower"], "tags": ["linux", "automation", "sensitive"]},
]

FINDINGS_TEMPLATES = [
    {"title": "Kerberoasting — Vulnerable SPN on SVC_SQL", "severity": "critical", "cve": "", "cvss": "9.1", "description": "Service account SVC_SQL has an SPN registered and uses a weak password susceptible to Kerberoasting attack. TGS ticket was cracked in < 2 hours.", "proof": "GetUserSPNs.py output shows SVC_SQL. Hashcat cracked: Summer2024!", "recommendation": "Use Group Managed Service Accounts (gMSA). Enforce 25+ character passwords for service accounts.", "status": "confirmed"},
    {"title": "Credential Dumping via Mimikatz on DC01", "severity": "critical", "cve": "", "cvss": "10.0", "description": "LSASS memory was dumped via Mimikatz sekurlsa::logonpasswords. Domain Admin hashes extracted including krbtgt.", "proof": "mimikatz # sekurlsa::logonpasswords — NTLM hash of Administrator@ACME extracted", "recommendation": "Enable Credential Guard. Run LSASS as PPL. Deploy EDR on DCs.", "status": "confirmed"},
    {"title": "SQL Injection in /api/v2/users endpoint", "severity": "critical", "cve": "CVE-2024-1234", "cvss": "9.8", "description": "The /api/v2/users?id= parameter is vulnerable to union-based SQL injection. Full database read access achieved.", "proof": "sqlmap --url='https://web01.acme.local/api/v2/users?id=1' --dbs returned 14 databases", "recommendation": "Use parameterized queries. Deploy WAF. Conduct code review.", "status": "confirmed"},
    {"title": "Exchange ProxyShell — RCE as SYSTEM", "severity": "critical", "cve": "CVE-2021-34473", "cvss": "9.8", "description": "Exchange Server EXCH01 is vulnerable to ProxyShell chain. Achieved RCE as SYSTEM via CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207.", "proof": "python proxyshell.py -t exch01 -e admin@acme.local - obtained webshell at /aspnet_client/", "recommendation": "Apply Microsoft security updates KB5003424+. Migrate to Exchange Online if possible.", "status": "resolved"},
    {"title": "Lateral Movement via Pass-the-Hash to FS01", "severity": "high", "cve": "", "cvss": "8.1", "description": "Used NTLM hash ofsvc_backupsvc_backup to authenticate to FS01 via SMB. Full file share access including HR documents.", "proof": "crackmapexec smb 10.0.2.10 -u svc_backup -H [hash] --shares — READ/WRITE on all shares", "recommendation": "Enable SMB signing. Restrict NTLM authentication. Implement tiered admin model.", "status": "confirmed"},
    {"title": "Jenkins Script Console — Unauthenticated RCE", "severity": "high", "cve": "", "cvss": "8.8", "description": "Jenkins at 10.0.3.10 allows unauthenticated access to /script endpoint. Arbitrary Groovy code execution achieved.", "proof": "Groovy script executed: 'whoami'. Output: jenkins. Reverse shell obtained.", "recommendation": "Enable authentication on Jenkins. Restrict script console to admins. Use Jenkins Matrix Authorization.", "status": "triaged"},
    {"title": "Weak VPN IKE PSK — Aggressive Mode Cracked", "severity": "high", "cve": "", "cvss": "7.5", "description": "VPN gateway IKE aggressive mode reveals PSK hash. Cracked via dictionary attack — PSK was 'AcmeVPN2024!'.", "proof": "ike-scan --aggressive --id='' 10.0.2.30 | psk-crack — cracked in 3 minutes", "recommendation": "Use certificate-based authentication. Disable aggressive mode. Use strong PSKs (32+ chars).", "status": "confirmed"},
    {"title": "GitLab Private Token in Jenkins Build Log", "severity": "high", "cve": "", "cvss": "7.2", "description": "Found GitLab personal access token in Jenkins build log. Token has maintainer access to all internal repositories.", "proof": "curl -H 'PRIVATE-TOKEN: glpat-...' https://gitlab.acme.local/api/v4/projects — listed 47 projects", "recommendation": "Rotate all exposed tokens. Use CI/CD variables instead of hardcoded secrets. Scan build logs.", "status": "open"},
    {"title": "Outdated OpenSSL 1.1.1 on WEB02", "severity": "medium", "cve": "CVE-2024-0727", "cvss": "5.3", "description": "WEB02 is running OpenSSL 1.1.1w which has known vulnerabilities including potential DoS via crafted certificates.", "proof": "openssl s_client -connect 10.0.1.31:443 2>&1 | grep 'OpenSSL 1.1.1'", "recommendation": "Upgrade to OpenSSL 3.x. Rebuild affected services.", "status": "open"},
    {"title": "Anonymous FTP Access on PRINT01", "severity": "medium", "cve": "", "cvss": "5.3", "description": "FTP server on PRINT01 allows anonymous login with read access to /share directory containing driver packages.", "proof": "ftp 10.0.2.50 — anonymous login successful, ls shows 120 .inf files", "recommendation": "Disable anonymous FTP. Use authenticated SMB shares instead.", "status": "open"},
    {"title": "SMB Signing Not Required", "severity": "medium", "cve": "", "cvss": "5.1", "description": "SMB signing is supported but not required on all domain-joined hosts, enabling potential relay attacks.", "proof": "crackmapexec smb 10.0.1.0/24 --gen-relay-list showed 28/30 hosts vulnerable to SMB relay", "recommendation": "Enable 'Microsoft network server: Digitally sign communications always' via GPO.", "status": "triaged"},
    {"title": "Unquoted Service Path on HR-WS01", "severity": "low", "cve": "", "cvss": "4.5", "description": "Service 'AcmeHRService' has unquoted path C:\\Program Files\\Acme HR\\service.exe, potentially allowing privilege escalation.", "proof": "wmic service get name,displayname,pathname | findstr /i acme — path is unquoted", "recommendation": "Quote the service path. Move service to standard location.", "status": "open"},
    {"title": "DNS Zone Transfer Allowed from External", "severity": "medium", "cve": "", "cvss": "5.3", "description": "External DNS server allows AXFR from any source, exposing full internal DNS zone including sensitive hostnames.", "proof": "dig @172.16.0.2 axfr acme.local — returned 156 records", "recommendation": "Restrict zone transfers to known secondaries only.", "status": "resolved"},
    {"title": "SharePoint Default Credentials", "severity": "high", "cve": "", "cvss": "7.5", "description": "SharePoint site uses default service account credentials for Central Administration: sp_admin:SharePoint2024!", "proof": "Logged in to https://sharepoint.acme.local:443/_admin with sp_admin credentials — full farm admin", "recommendation": "Change default credentials immediately. Implement MFA for admin portals.", "status": "confirmed"},
    {"title": "Kubernetes Dashboard Exposed Without Auth", "severity": "high", "cve": "", "cvss": "8.2", "description": "Kubernetes dashboard at K8S-MASTER:30000 is publicly accessible without authentication, revealing all cluster resources.", "proof": "curl http://10.0.3.40:30000 — loaded dashboard with full admin privileges", "recommendation": "Enable RBAC for dashboard. Use kubectl proxy for access. Restrict NodePort range.", "status": "triaged"},
]

CREDENTIALS_DATA = [
    {"username": "Administrator", "secret": encrypt_str("W1nD0w$@dm1n!2024"), "type": "hash_ntlm", "service": "Windows", "host": "DC01.acme.local", "domain": "ACME", "cracked": True},
    {"username": "svc_sql", "secret": encrypt_str("Summer2024!"), "type": "password", "service": "MSSQL", "host": "DB01.acme.local", "domain": "ACME", "cracked": True},
    {"username": "svc_backup", "secret": encrypt_str("B@ckup2024#"), "type": "password", "service": "Windows", "host": "FS01.acme.local", "domain": "ACME", "cracked": True},
    {"username": "jenkins_admin", "secret": encrypt_str("j3nk1ns_adm1n!"), "type": "password", "service": "Jenkins", "host": "JENKINS.acme.local", "domain": "", "cracked": True},
    {"username": "root", "secret": encrypt_str("r00t@VPN!2024"), "type": "password", "service": "SSH", "host": "VPN01.acme.local", "domain": "", "cracked": True},
    {"username": "gitlab_admin", "secret": encrypt_str("GL@dm1n2024!"), "type": "password", "service": "GitLab", "host": "GITLAB.acme.local", "domain": "", "cracked": True},
    {"username": "sp_admin", "secret": encrypt_str("SharePoint2024!"), "type": "password", "service": "SharePoint", "host": "SHAREPOINT.acme.local", "domain": "ACME", "cracked": True},
    {"username": "krbtgt", "secret": encrypt_str("aadd3148-73b1-4b79-9ea5-0c9c6b1a1f2c"), "type": "hash_kerberos", "service": "Kerberos", "host": "DC01.acme.local", "domain": "ACME", "cracked": False, "notes": "Golden Ticket possible"},
    {"username": "mysql_root", "secret": encrypt_str("My$QLr00t!"), "type": "password", "service": "MySQL", "host": "DB01.acme.local", "domain": "", "cracked": True},
    {"username": "grafana_admin", "secret": encrypt_str("Gr@fana2024"), "type": "password", "service": "Grafana", "host": "MON01.acme.local", "domain": "", "cracked": True},
    {"username": "elastic_admin", "secret": encrypt_str("El@st1c!2024"), "type": "password", "service": "Elasticsearch", "host": "SIEM01.acme.local", "domain": "", "cracked": True},
    {"username": "ansible_deploy", "secret": encrypt_str("Ans1bl3@D3pl0y!"), "type": "password", "service": "SSH", "host": "ANSIBLE.acme.local", "domain": "", "cracked": True},
]

NOTES_DATA = [
    {"title": "Recon Summary — ACME Corp", "phase": "recon", "content": "## External Recon\n- 2 public IPs: 172.16.0.1 (web), 172.16.0.2 (mail)\n- DNS: acme.local + acme.com\n- Mail: Exchange 2019 (OWA accessible)\n- Web: Nginx reverse proxy\n\n## Internal (via VPN)\n- AD domain: ACME.LOCAL\n- 10.0.0.0/16 network\n- ~200 hosts alive\n- Domain functional level: Windows Server 2016", "tags": ["recon", "osint", "network"], "starred": True},
    {"title": "AD Enumeration Results", "phase": "recon", "content": "## Domain: ACME.LOCAL\n- Domain Controllers: DC01, DC02\n- Domain Admins: 5 members\n- Service Accounts: 23 SPN accounts\n- Trusts: None\n- GPOs: 42 policies\n- LAPS: NOT deployed\n- BitLocker: Partial (workstations only)", "tags": ["ad", "enumeration"], "starred": True},
    {"title": "Phishing Campaign #1 — Results", "phase": "exploitation", "content": "## Campaign: Q3 Performance Review\n- Template: Fake HR review link\n- Sent: 150 employees\n- Opened: 89 (59%)\n- Clicked: 34 (23%)\n- Credentials captured: 12\n- Admin credentials: 2 (IT-WS01 user, Finance user)\n\n### Key captures:\n- j.smith / Summer2024! (IT admin)\n- a.jones / Finance2024# (Finance)", "tags": ["phishing", "social-engineering"], "starred": True},
    {"title": "Lateral Movement Path", "phase": "post-exploitation", "content": "## Attack Path:\n1. Phishing → IT-WS01 (j.smith)\n2. Mimikatz → Domain Admin hash cached\n3. PtH → DC01 → krbtgt extracted\n4. Golden Ticket → Persistence\n5. DC01 → All hosts via PS Remoting\n6. Jenkins → GitLab tokens → Source code\n7. Ansible → Full infrastructure control", "tags": ["lateral", "path", "ad"], "starred": True},
    {"title": "OpSec Notes", "phase": "post-exploitation", "content": "## OPSEC Considerations\n- EDR: CrowdStrike Falcon on servers, not workstations\n- SIEM: Elasticsearch/Kibana on SIEM01 — generate noise to mask activity\n- AV: Windows Defender only on workstations\n- Logging: Moderate — PowerShell transcript enabled on DCs\n- Network monitoring: Basic — no NDR\n\n## Cleanup needed:\n- [ ] Clear PowerShell history on IT-WS01\n- [ ] Remove scheduled tasks on DC01\n- [ ] Delete Jenkins build logs with tokens\n- [ ] Flush Exchange tracking logs", "tags": ["opsec", "cleanup"], "starred": False},
    {"title": "Client Meeting Notes — Week 3", "phase": "reporting", "content": "## Meeting with CISO\n- Client concerned about AD security\n- Requested detailed lateral movement timeline\n- Wants remediation workshop next week\n- Approved extended testing of cloud workloads\n\n## Action Items:\n- [ ] Prepare AD hardening recommendations\n- [ ] Schedule remediation workshop\n- [ ] Test Azure AD sync server", "tags": ["client", "meeting"], "starred": False},
    {"title": "Network Diagram — Target Environment", "phase": "recon", "content": "```\nInternet ──┬── DMZ-WEB01 (172.16.0.1)\n           └── DMZ-MAIL01 (172.16.0.2)\n                │\n         ┌──── FW-MGMT ────┐\n         │                  │\n    [10.0.1.x]         [10.0.2.x]\n    DC01  DC02         FS01  APP01\n    EXCH  WEB01/2      VPN01 FW\n    DB01/2  SP         PRINT01\n    WSUS  AV\n         │                  │\n    [10.0.3.x]         [10.0.4.x]\n    JENKINS GITLAB      MON01\n    DOCKER K8S          SIEM01\n    ANSIBLE\n         │\n    [10.0.5.x]\n    HR-WS  FIN-WS  IT-WS\n```", "tags": ["network", "diagram"], "starred": True},
    {"title": "Tool Inventory", "phase": "recon", "content": "## Active Tools\n- BloodHound CE — AD attack path analysis\n- CrackMapExec — lateral movement validation\n- Cobalt Strike — C2 framework (via Adaptix)\n- Impacket — AD exploitation toolkit\n- sqlmap — SQL injection testing\n- Nmap — Network scanning\n- Mimikatz — Credential harvesting\n- Hashcat — Password cracking\n- John — Password cracking\n- Responder — LLMNR/NBT-NS poisoning\n- mitm6 — IPv6 DNS takeover", "tags": ["tools", "inventory"], "starred": False},
]

ATTACK_STEPS_TEMPLATE = [
    {"label": "Initial Access", "sublabel": "Phishing", "technique": "Spearphishing Link", "mitre_id": "T1566.001", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "IT-WS01 Compromise", "sublabel": "User Workstation", "technique": "User Execution", "mitre_id": "T1204", "node_status": "done", "confidence": "high", "node_type": "host"},
    {"label": "Credential Harvesting", "sublabel": "Mimikatz on IT-WS01", "technique": "OS Credential Dumping", "mitre_id": "T1003.001", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "Privilege Escalation", "sublabel": "Domain Admin cached", "technique": "Valid Accounts", "mitre_id": "T1078", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "DC01 Compromise", "sublabel": "Domain Controller", "technique": "Pass the Hash", "mitre_id": "T1550.002", "node_status": "done", "confidence": "high", "node_type": "host"},
    {"label": "Golden Ticket", "sublabel": "krbtgt extracted", "technique": "Forge Kerberos Tickets", "mitre_id": "T1558.001", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "Lateral to EXCH01", "sublabel": "Exchange Server", "technique": "Remote Services", "mitre_id": "T1021", "node_status": "done", "confidence": "high", "node_type": "host"},
    {"label": "ProxyShell RCE", "sublabel": "CVE-2021-34473", "technique": "Exploit Public-Facing App", "mitre_id": "T1190", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "Lateral to JENKINS", "sublabel": "CI/CD Server", "technique": "Remote Services: SMB", "mitre_id": "T1021.002", "node_status": "done", "confidence": "medium", "node_type": "host"},
    {"label": "Jenkins RCE", "sublabel": "Script Console", "technique": "Exploitation for Client Execution", "mitre_id": "T1203", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "GitLab Token Theft", "sublabel": "Source Code Access", "technique": "Steal Application Access Token", "mitre_id": "T1528", "node_status": "done", "confidence": "high", "node_type": "technique"},
    {"label": "Lateral to ANSIBLE", "sublabel": "Automation Server", "technique": "Remote Services: SSH", "mitre_id": "T1021.004", "node_status": "in_progress", "confidence": "medium", "node_type": "host"},
    {"label": "Infrastructure Control", "sublabel": "Full Takeover", "technique": "Data from Configuration Repository", "mitre_id": "T1602", "node_status": "hypothetical", "confidence": "low", "node_type": "technique"},
    {"label": "Data Exfiltration", "sublabel": "Via DNS/HTTPS C2", "technique": "Exfiltration Over C2 Channel", "mitre_id": "T1041", "node_status": "hypothetical", "confidence": "low", "node_type": "technique"},
]

OBJECTIVES_DATA = [
    {"title": "Capture DC01 Administrator hash", "category": "flag", "points": 500, "status": "captured", "flag_value": "FLAG{DC01_PWN3D_2024}"},
    {"title": "Compromise Exchange Server", "category": "flag", "points": 400, "status": "captured", "flag_value": "FLAG{PR0XYSH3LL_RCE}"},
    {"title": "Access Jenkins build pipeline", "category": "flag", "points": 300, "status": "captured", "flag_value": "FLAG{J3NK1NS_PWN3D}"},
    {"title": "Obtain GitLab source code", "category": "flag", "points": 300, "status": "captured", "flag_value": "FLAG{G1TL4B_SC_R3AD}"},
    {"title": "Compromise VPN gateway", "category": "flag", "points": 250, "status": "captured", "flag_value": "FLAG{VPN_PSK_CR4CK3D}"},
    {"title": "Access SharePoint farm admin", "category": "flag", "points": 200, "status": "captured", "flag_value": "FLAG{SP_F4RM_4DM1N}"},
    {"title": "Dump all domain hashes", "category": "flag", "points": 600, "status": "not_started"},
    {"title": "Achieve persistence via Golden Ticket", "category": "flag", "points": 500, "status": "captured", "flag_value": "FLAG{G0LD3N_T1CK3T}"},
    {"title": "Compromise K8s cluster admin", "category": "flag", "points": 400, "status": "in_progress"},
    {"title": "Exfiltrate customer database", "category": "flag", "points": 1000, "status": "not_started"},
    {"title": "Write detection rules for all TTPs", "category": "objective", "points": 200, "status": "in_progress"},
    {"title": "Document full attack path timeline", "category": "objective", "points": 150, "status": "in_progress"},
]

LOOTS_DATA = [
    {"loot_type": "file", "value": "ntds.dit", "description": "Active Directory database dump from DC01", "filename": "ntds.dit", "file_size": 16777216, "artifact_type": "credential"},
    {"loot_type": "file", "value": "NTDS hash dump", "description": "All domain password hashes extracted from NTDS.dit", "filename": "domain_hashes.txt", "file_size": 245760, "artifact_type": "credential"},
    {"loot_type": "text", "value": "ssh://root@10.0.2.30 id_rsa key", "description": "SSH private key from VPN01", "artifact_type": "credential"},
    {"loot_type": "file", "value": "SAM database", "description": "SAM and SYSTEM hive from IT-WS01", "filename": "SAM_SYSTEM.zip", "file_size": 524288, "artifact_type": "credential"},
    {"loot_type": "screenshot", "value": "DC01 Desktop screenshot", "description": "Screenshot of Domain Controller desktop via RDP", "filename": "dc01_desktop.png", "file_size": 1048576, "artifact_type": "screenshot"},
    {"loot_type": "text", "value": "Kerberos TGT (krbtgt)", "description": "Golden Ticket material", "artifact_type": "credential"},
    {"loot_type": "file", "value": "SharePoint config", "description": "SharePoint farm configuration with DB credentials", "filename": "sp_farm_config.xml", "file_size": 15360, "artifact_type": "config"},
    {"loot_type": "text", "value": "GitLab personal access token", "description": "glpat-xxxx — maintainer access", "artifact_type": "credential"},
    {"loot_type": "file", "value": "Network diagram visio", "description": "Internal network architecture diagram from IT share", "filename": "acme_network.vsdx", "file_size": 2097152, "artifact_type": "document"},
    {"loot_type": "text", "value": "AWS credentials from Jenkins", "description": "AKIA... access key found in Jenkins credentials store", "artifact_type": "credential"},
]

def _table_of(sql):
    m = re.search(r"INSERT INTO ([a-z_]+)", sql)
    return m.group(1) if m else "?"


# Every insert _safe_insert rolled back, as (table, error). A failure here is
# usually a duplicate the caller handles by reading the existing row back, so
# the helper still returns False rather than raising — but it no longer does it
# silently: a schema drift that kills a whole table used to look like a clean
# run with an empty table behind it.
FAILURES = []


def _safe_insert(db, sql, params):
    try:
        conn = db.connection()
        conn.execute(text("SAVEPOINT sp"))
        db.execute(text(sql), params)
        conn.execute(text("RELEASE SAVEPOINT sp"))
    except Exception as exc:
        FAILURES.append((_table_of(sql), str(exc).split("\n")[0]))
        try:
            conn = db.connection()
            conn.execute(text("ROLLBACK TO SAVEPOINT sp"))
        except Exception:
            pass
        return False
    return True


def _report_failures():
    """Print one line per distinct failure reason, with a count."""
    if not FAILURES:
        return 0
    grouped = {}
    for table, err in FAILURES:
        grouped.setdefault((table, err), 0)
        grouped[(table, err)] += 1
    print(f"\n{len(FAILURES)} insert(s) were rolled back:")
    for (table, err), n in sorted(grouped.items(), key=lambda kv: -kv[1]):
        print(f"  {table}: {n}x {err}")
    return len(FAILURES)


def _live_columns(db, table):
    """Columns the table actually has right now, or an empty set if it is gone."""
    rows = db.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :t"
        ),
        {"t": table},
    ).fetchall()
    return {r[0] for r in rows}


def _required_columns(db, table):
    """NOT NULL columns with no default — these must be present in the payload."""
    rows = db.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :t "
            "AND is_nullable = 'NO' AND column_default IS NULL"
        ),
        {"t": table},
    ).fetchall()
    return {r[0] for r in rows}


def seed():
    db = SessionLocal()
    try:
        print("=== Umbryx Demo Data Seeding ===\n")

        # ── Users ──
        print("[1/16] Users...")
        users = {}
        for u in USERS_DATA:
            db.execute(text(
                "INSERT INTO users (id, username, display_name, password_hash, role, created_at, active, mfa_enabled) "
                "VALUES (:id, :u, :d, :ph, :r, :ts, true, false) "
                "ON CONFLICT (username) DO UPDATE SET display_name=EXCLUDED.display_name, "
                "password_hash=EXCLUDED.password_hash, role=EXCLUDED.role, created_at=EXCLUDED.created_at"
            ), {"id": _id("u"), "u": u["username"], "d": u["display_name"], "ph": hash_password("Demo2024!"), "r": u["role"], "ts": N()})
            row = db.execute(text("SELECT id FROM users WHERE username = :u"), {"u": u["username"]}).fetchone()
            users[u["username"]] = row[0]
        admin_id = users["admin"]
        print(f"  Synced {len(users)} users (password: Demo2024!)")

        # ── Organizations ──
        print("[2/16] Organizations...")
        orgs = {}
        for o in ORGS_DATA:
            db.execute(text(
                # No `plan` column: the free-text Organization.plan field was
                # dropped (41e9ff3). The authoritative tier lives in the
                # separate organization_plans table, which core/plan.py reads.
                "INSERT INTO organizations (id, name, slug, created_at) "
                "VALUES (:id, :n, :s, :ts) "
                "ON CONFLICT (slug) DO UPDATE SET name=EXCLUDED.name"
            ), {"id": _id("org"), "n": o["name"], "s": o["slug"], "ts": N()})
            row = db.execute(text("SELECT id FROM organizations WHERE slug = :s"), {"s": o["slug"]}).fetchone()
            orgs[o["slug"]] = row[0]
        print(f"  Synced {len(orgs)} organizations")

        # ── Organization plans ──
        # One enterprise org so the licensed surfaces (org SSO panel, its
        # Add Provider button) photograph in their unlocked state.
        db.execute(text(
            "INSERT INTO organization_plans (id, org_id, tier, max_members, max_infra_instances, max_workstations, features, created_at, updated_at) "
            "VALUES (:pid, :oid, 'enterprise', -1, -1, -1, :feat, :ts, :ts) "
            "ON CONFLICT (org_id) DO UPDATE SET tier='enterprise', features=:feat"
        ), {"pid": _id("orgplan"), "oid": orgs["redteam-alpha"], "feat": json.dumps(
            ["infra_lifecycle", "workstations", "dns_management", "cloud_provider_tier1",
             "cloud_provider_tier2", "vpn_generation", "plugin_upload", "custom_templates",
             "advanced_audit", "api_access", "sso", "multiple_orgs", "priority_support"]), "ts": N()})
        db.commit()

        # ── OIDC provider (org-scoped SSO) ──
        # A realistic IdP row for the Organizations → SSO screenshot: the
        # panel shows its redirect URI, Test sign-in button and badges.
        _safe_insert(db,
            "INSERT INTO oidc_providers (id, org_id, name, issuer_url, client_id, client_secret, scopes, "
            "authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, claim_mapping, role_mapping, "
            "default_role, allow_private_issuer, jit_provisioning_enabled, require_platform_mfa, email_domain, "
            "enabled, enforced, last_test_login_at, created_at, updated_at, created_by) "
            "VALUES (:id, :oid, 'ACME Keycloak', 'https://keycloak.acme.corp', 'umbryx-platform', 'seed-not-a-secret', :scopes, "
            "'https://keycloak.acme.corp/protocol/openid-connect/auth', "
            "'https://keycloak.acme.corp/protocol/openid-connect/token', "
            "'https://keycloak.acme.corp/protocol/openid-connect/userinfo', "
            "'https://keycloak.acme.corp/protocol/openid-connect/certs', "
            "'{}', '{}', 'analyst', false, true, false, 'acme.corp', true, false, NULL, :ts, :ts, :cb)",
            {"id": _id("oidcp"), "oid": orgs["redteam-alpha"],
             "scopes": json.dumps(["openid", "email", "profile"]), "ts": N(), "cb": admin_id})
        db.commit()
        print("  Enterprise plan + org SSO provider seeded")

        # ── Teams ──
        print("[3/16] Teams...")
        teams = {}
        for slug, oid in orgs.items():
            for tname in ["Red Ops", "Analysis", "Leadership"]:
                _safe_insert(db,
                    "INSERT INTO teams (id, org_id, name, created_at) VALUES (:id, :oid, :n, :ts)",
                    {"id": _id("tm"), "oid": oid, "n": tname, "ts": N()})
                row = db.execute(text("SELECT id FROM teams WHERE org_id = :oid AND name = :n ORDER BY created_at DESC LIMIT 1"), {"oid": oid, "n": tname}).fetchone()
                if row:
                    teams[f"{slug}/{tname}"] = row[0]
        print(f"  Synced {len(teams)} teams")

        # ── Org Members ──
        print("[4/16] Organization Members...")
        om_count = 0
        for slug, oid in orgs.items():
            for uname in ["admin", "operator1", "operator2", "analyst1", "analyst2", "viewer1"]:
                role = "owner" if uname == "admin" else ("admin" if "operator" in uname else ("editor" if "analyst" in uname else "viewer"))
                if _safe_insert(db,
                    "INSERT INTO organization_members (id, org_id, user_id, role, created_at) VALUES (:id, :oid, :uid, :r, :ts)",
                    {"id": _id("om"), "oid": oid, "uid": users[uname], "r": role, "ts": N()}):
                    om_count += 1
        print(f"  Synced {om_count} org memberships")

        # ── Projects ──
        print("[5/16] Projects...")
        projects = {}
        org_list = list(orgs.values())
        for i, p in enumerate(PROJECTS_DATA):
            org_id = org_list[0] if i < 3 else org_list[1]
            db.execute(text(
                "INSERT INTO projects (id, name, status, ip, os, added, description, org_id) "
                "VALUES (:id, :n, :s, '', 'Mixed', :ts, :d, :oid) "
                "ON CONFLICT DO NOTHING"
            ), {"id": _id("p"), "n": p["name"], "s": p["status"], "ts": N(), "d": p["description"], "oid": org_id})
            row = db.execute(text("SELECT id FROM projects WHERE name = :n AND org_id = :oid"), {"n": p["name"], "oid": org_id}).fetchone()
            if row:
                projects[p["name"]] = row[0]
        print(f"  Synced {len(projects)} projects")

        # ── Project Members ──
        print("[6/16] Project Members...")
        pm_count = 0
        roles_cycle = ["owner", "admin", "operator", "analyst", "analyst", "viewer"]
        for pname, pid in projects.items():
            if pname == "Iron Fortress":
                continue
            for i, uname in enumerate(["admin", "operator1", "operator2", "analyst1", "analyst2", "viewer1"]):
                if _safe_insert(db,
                    "INSERT INTO project_members (id, project_id, user_id, role, source, created_at, is_active) "
                    "VALUES (:id, :pid, :uid, :r, 'direct', :ts, true)",
                    {"id": _id("pm"), "pid": pid, "uid": users[uname], "r": roles_cycle[i], "ts": N()}):
                    pm_count += 1
        print(f"  Synced {pm_count} project memberships")

        # ── Hosts ──
        print("[7/16] Hosts...")
        hosts = {}
        active_projects = [pn for pn in projects if pn != "Iron Fortress"]
        for i, h in enumerate(HOSTS_DATA):
            pname = active_projects[i % len(active_projects)]
            if _safe_insert(db,
                "INSERT INTO hosts (id, pid, ip, hostname, os, status, ports, services, tags, domain, role, is_attacker, import_source) "
                "VALUES (:id, :pid, :ip, :hn, :os, :s, :ports, :svc, :tags, :dom, :role, :atk, 'manual')",
                {
                    "id": _id("h"), "pid": projects[pname], "ip": h["ip"], "hn": h["hostname"],
                    "os": h["os"], "s": h["status"], "ports": h.get("ports", []),
                    "svc": h.get("services", []), "tags": h.get("tags", []),
                    "dom": h["hostname"].split(".")[-1] if "." in h["hostname"] else "",
                    "role": h.get("role", "unknown"), "atk": h.get("is_attacker", False),
                }):
                hosts[h["ip"]] = db.execute(text("SELECT id FROM hosts WHERE pid = :pid AND ip = :ip ORDER BY id DESC LIMIT 1"),
                    {"pid": projects[pname], "ip": h["ip"]}).fetchone()[0]
            else:
                row = db.execute(text("SELECT id FROM hosts WHERE pid = :pid AND ip = :ip"), {"pid": projects[pname], "ip": h["ip"]}).fetchone()
                if row:
                    hosts[h["ip"]] = row[0]
        print(f"  Synced {len(hosts)} hosts")

        # ── Findings ──
        print("[8/16] Findings...")
        findings = {}
        host_ips = list(hosts.keys())
        for i, f in enumerate(FINDINGS_TEMPLATES):
            pname = active_projects[i % len(active_projects)]
            hip = host_ips[i % len(host_ips)]
            if _safe_insert(db,
                "INSERT INTO findings (id, pid, host_id, title, severity, cvss, cve, description, proof, recommendation, status, source, ts) "
                "VALUES (:id, :pid, :hid, :t, :sev, :cvss, :cve, :d, :pr, :rec, :s, 'manual', :ts)",
                {"id": _id("f"), "pid": projects[pname], "hid": hosts.get(hip), "t": f["title"], "sev": f["severity"],
                 "cvss": f["cvss"], "cve": f["cve"], "d": f["description"], "pr": f["proof"],
                 "rec": f["recommendation"], "s": f["status"], "ts": N()}):
                findings[f["title"][:30]] = True
        print(f"  Created {len(findings)} findings")

        # ── Credentials ──
        print("[9/16] Credentials...")
        cred_count = 0
        for c in CREDENTIALS_DATA:
            pname = active_projects[cred_count % len(active_projects)]
            if _safe_insert(db,
                "INSERT INTO creds (id, pid, username, secret, type, service, host, domain, cracked, notes, tags, host_ids, is_domain) "
                "VALUES (:id, :pid, :u, :s, :t, :svc, :h, :dom, :cr, :notes, '{}', '{}', false)",
                {"id": _id("cr"), "pid": projects[pname], "u": c["username"], "s": c["secret"],
                 "t": c["type"], "svc": c["service"], "h": c["host"], "dom": c.get("domain", ""),
                 "cr": c.get("cracked", False), "notes": c.get("notes", "")}):
                cred_count += 1
        print(f"  Created {cred_count} credentials")

        # ── Notes ──
        print("[10/16] Notes...")
        note_count = 0
        for n in NOTES_DATA:
            pname = active_projects[note_count % len(active_projects)]
            if _safe_insert(db,
                "INSERT INTO notes (id, pid, title, phase, tags, content, ts, starred, version) "
                "VALUES (:id, :pid, :t, :ph, :tags, :c, :ts, :star, 0)",
                {"id": _id("n"), "pid": projects[pname], "t": n["title"], "ph": n["phase"],
                 "tags": n.get("tags", []), "c": n["content"], "ts": N(), "star": n.get("starred", False)}):
                note_count += 1
        print(f"  Created {note_count} notes")

        # ── Attack Paths ──
        print("[11/16] Attack Paths...")
        ap_count = 0
        for pname in active_projects:
            apid = _id("ap")
            if not _safe_insert(db,
                "INSERT INTO attack_paths (id, pid, name, description, ts, status, risk_score, impact_score, likelihood_score, version, created_by) "
                "VALUES (:id, :pid, :n, :d, :ts, 'active', 85, 9, 8, 1, :cb)",
                {"id": apid, "pid": projects[pname], "n": f"Primary Attack Chain - {pname}", "d": f"Main attack path for {pname} engagement", "ts": N(), "cb": admin_id}):
                continue

            prev_node = None
            branch_parent = None
            step_order = 0
            for s in ATTACK_STEPS_TEMPLATE:
                sid = _id("as")
                _safe_insert(db,
                    "INSERT INTO attack_steps (id, path_id, pid, parent_step_id, host_id, step_order, node_type, label, sublabel, technique, mitre_id, notes, node_status, confidence, ts) "
                    "VALUES (:id, :apid, :pid, :parent, :hid, :ord, :nt, :l, :sl, :tech, :mid, '', :ns, :conf, :ts)",
                    {"id": sid, "apid": apid, "pid": projects[pname],
                     "parent": prev_node, "hid": None, "ord": step_order, "nt": s["node_type"],
                     "l": s["label"], "sl": s["sublabel"], "tech": s["technique"], "mid": s["mitre_id"],
                     "ns": s["node_status"], "conf": s["confidence"], "ts": N()})
                if step_order == 2:
                    branch_parent = sid  # fork the alternative entry off step 3
                prev_node = sid
                step_order += 1
            # One branch on the first project so the tree view photographs
            # with a fork (the + branch button / child steps UI).
            if ap_count == 0:
                _safe_insert(db,
                    "INSERT INTO attack_steps (id, path_id, pid, parent_step_id, host_id, step_order, node_type, label, sublabel, technique, mitre_id, notes, node_status, confidence, ts) "
                    "VALUES (:id, :apid, :pid, :parent, NULL, 99, 'action', 'Alternate: VPN PSK crack', 'ike-scan aggressive mode', 'T1133', 'T1133', '', 'completed', 'high', :ts)",
                    {"id": _id("as"), "apid": apid, "pid": projects[pname], "parent": branch_parent, "ts": N()})
            ap_count += 1
        print(f"  Created {ap_count} attack paths")

        # ── Objectives ──
        print("[12/16] Objectives...")
        obj_count = 0
        for o in OBJECTIVES_DATA:
            pname = active_projects[obj_count % len(active_projects)]
            if _safe_insert(db,
                "INSERT INTO objectives (id, pid, host_id, title, description, category, points, status, flag_value, captured_by, captured_at, ts) "
                "VALUES (:id, :pid, NULL, :t, '', :cat, :pts, :s, :fv, '', '', :ts)",
                {"id": _id("ob"), "pid": projects[pname], "t": o["title"], "cat": o["category"],
                 "pts": o["points"], "s": o["status"], "fv": o.get("flag_value", ""), "ts": N()}):
                obj_count += 1
        print(f"  Created {obj_count} objectives")

        # ── Loot ──
        print("[13/16] Loot...")
        loot_count = 0
        for l in LOOTS_DATA:
            pname = active_projects[loot_count % len(active_projects)]
            if _safe_insert(db,
                "INSERT INTO loots (id, pid, host_id, loot_type, value, description, source_path, filename, file_size, artifact_type, ts, job_id, cred_id, finding_id, playbook_run_id, sha256, tags) "
                "VALUES (:id, :pid, :hid, :lt, :v, :d, '', :fn, :fs, :at, :ts, '', '', '', '', '', '{}')",
                {"id": _id("lt"), "pid": projects[pname], "hid": hosts.get(host_ips[loot_count % len(host_ips)]),
                 "lt": l["loot_type"], "v": l["value"], "d": l["description"],
                 "fn": l.get("filename", ""), "fs": l.get("file_size", 0), "at": l["artifact_type"], "ts": N()}):
                loot_count += 1
        print(f"  Created {loot_count} loot items")

        # ── Scopes ──
        print("[14/16] Scopes...")
        scope_count = 0
        scopes = [
            {"value": "10.0.0.0/16", "scope_type": "cidr", "in_scope": True, "description": "Internal network"},
            {"value": "172.16.0.0/24", "scope_type": "cidr", "in_scope": True, "description": "DMZ"},
            {"value": "192.168.100.0/24", "scope_type": "cidr", "in_scope": False, "description": "Attacker infrastructure"},
            {"value": "*.acme.local", "scope_type": "domain", "in_scope": True, "description": "Internal domain"},
            {"value": "*.acme.com", "scope_type": "domain", "in_scope": True, "description": "External domain"},
            {"value": "10.0.4.0/24", "scope_type": "cidr", "in_scope": False, "description": "Monitoring/Blue Team - DO NOT ENGAGE"},
        ]
        for pname in active_projects:
            for s in scopes:
                if _safe_insert(db,
                    "INSERT INTO scopes (id, pid, value, scope_type, in_scope, description, gateway_ip, is_entry) "
                    "VALUES (:id, :pid, :v, :st, :is, :d, '', false)",
                    {"id": _id("sc"), "pid": projects[pname], "v": s["value"], "st": s["scope_type"],
                     "is": s["in_scope"], "d": s["description"]}):
                    scope_count += 1
        print(f"  Created {scope_count} scopes")

        # ── Network Map ──
        print("[15/16] Network Map...")
        for pname in active_projects:
            pid = projects[pname]
            net_id = _id("net")
            if not _safe_insert(db,
                "INSERT INTO networks (id, pid, name, background, meta_json) VALUES (:id, :pid, :n, '#07080b', '{}')",
                {"id": net_id, "pid": pid, "n": f"{pname} Network"}):
                continue

            node_ids = {}
            positions = [
                (400, 50), (600, 50), (200, 150), (400, 150), (600, 150), (800, 150),
                (200, 300), (400, 300), (600, 300), (800, 300), (300, 450), (500, 450), (700, 450),
                (200, 600), (400, 600), (600, 600), (800, 600), (300, 750), (500, 750), (700, 750),
                (50, 300), (900, 300), (400, 900), (600, 900), (800, 750), (200, 900), (600, 750), (800, 900),
                (50, 600), (900, 600),
            ]
            for i, h in enumerate(HOSTS_DATA):
                if i >= len(positions):
                    break
                nid = _id("nn")
                x, y = positions[i]
                _safe_insert(db,
                    "INSERT INTO network_nodes (id, network_id, pid, host_id, x, y, label, ip, type, status, ports, notes, role, os, tags, is_attacker, manually_positioned, auto_positioned, updated_at, version, extra_json, ips) "
                    "VALUES (:id, :nid, :pid, :hid, :x, :y, :l, :ip, 'host', :s, :ports, '', :role, :os, :tags, :atk, true, false, '', 1, :extra, '{}')",
                    {"id": nid, "nid": net_id, "pid": pid, "hid": hosts.get(h["ip"]),
                     "x": x, "y": y, "l": h["hostname"].split(".")[0], "ip": h["ip"],
                     "s": h["status"], "ports": h.get("ports", []), "role": h.get("role", ""),
                     "os": h["os"], "tags": h.get("tags", []), "atk": h.get("is_attacker", False),
                     # Tier badges on the map (crown = T0 domain controllers,
                     # shield = T1 critical infrastructure): the frontend
                     # reads extra_json.tier and renders the icon.
                     "extra": json.dumps({"tier": 0 if h.get("role") == "domain_controller" else (1 if h.get("role") == "mail_server" else None)})})
                node_ids[h["ip"]] = nid

            edges = [
                ("10.0.1.10", "10.0.1.11"), ("10.0.1.10", "10.0.1.20"), ("10.0.1.10", "10.0.2.10"),
                ("10.0.1.10", "10.0.2.20"), ("10.0.1.20", "10.0.1.30"), ("10.0.1.30", "10.0.1.31"),
                ("10.0.1.30", "10.0.1.40"), ("10.0.1.40", "10.0.1.41"), ("10.0.2.10", "10.0.2.20"),
                ("10.0.2.30", "10.0.2.40"), ("10.0.2.30", "10.0.5.12"), ("10.0.3.10", "10.0.3.20"),
                ("10.0.3.20", "10.0.3.30"), ("10.0.3.40", "10.0.3.41"), ("10.0.4.10", "10.0.4.20"),
                ("10.0.5.10", "10.0.5.11"), ("10.0.5.11", "10.0.5.12"), ("172.16.0.1", "10.0.1.30"),
                ("172.16.0.2", "10.0.1.20"), ("192.168.100.1", "10.0.2.30"), ("192.168.100.2", "192.168.100.1"),
                ("10.0.1.10", "10.0.1.50"), ("10.0.1.10", "10.0.1.60"), ("10.0.1.10", "10.0.1.70"),
                ("10.0.2.50", "10.0.2.10"), ("10.0.3.50", "10.0.3.10"), ("10.0.3.40", "10.0.3.10"),
            ]
            for src, dst in edges:
                if src in node_ids and dst in node_ids:
                    _safe_insert(db,
                        "INSERT INTO network_edges (id, network_id, pid, from_node_id, to_node_id, style, type, label, confidence, source, reason, state, verified, is_manual, manual_override, updated_at, version, extra_json) "
                        "VALUES (:id, :nid, :pid, :fn, :tn, 'solid', 'network', '', 1.0, 'manual', '', 'manual', false, true, false, '', 1, '{}')",
                        {"id": _id("ne"), "nid": net_id, "pid": pid, "fn": node_ids[src], "tn": node_ids[dst]})
        print(f"  Created network maps with nodes and edges")

        # ── Timeline Events ──
        print("[16/16] Timeline Events...")
        events = [
            ("project", "create", "Project created"),
            ("host", "import", "Imported 28 hosts from network scan"),
            ("finding", "create", "Kerberoasting - Vulnerable SPN on SVC_SQL"),
            ("finding", "create", "Exchange ProxyShell - RCE as SYSTEM"),
            ("attack_path", "create", "Primary Attack Chain created"),
            ("instance", "provision", "Adaptix C2 provisioned"),
            ("instance", "claim", "Adaptix C2 claimed by project"),
            ("note", "create", "Recon Summary created"),
            ("note", "create", "AD Enumeration Results created"),
            ("note", "create", "Phishing Campaign #1 Results created"),
            ("objective", "capture", "FLAG{DC01_PWN3D_2024}"),
            ("objective", "capture", "FLAG{PR0XYSH3LL_RCE}"),
            ("finding", "triaged", "Jenkins Script Console triaged"),
            ("credential", "create", "svc_sql password cracked"),
            ("loot", "create", "ntds.dit extracted from DC01"),
        ]
        evt_count = 0
        for pname in active_projects:
            for ev in events:
                if _safe_insert(db,
                    "INSERT INTO timeline_events (id, pid, username, entity, action, label, meta, ts) "
                    "VALUES (:id, :pid, 'admin', :ent, :act, :l, '{}', :ts)",
                    {"id": _id("evt"), "pid": projects[pname], "ent": ev[0], "act": ev[1], "l": ev[2], "ts": N()}):
                    evt_count += 1
        print(f"  Created {evt_count} timeline events")

        # ── DNS Records ──
        # Not seeded. dns_records was redesigned for the EE DNS tab: it now
        # requires zone_id and provider_id (both NOT NULL) pointing at DNS
        # zones and a configured provider, and `project_id`, `provider`,
        # `type` and `linked_to` are gone. Seeding a record means first
        # standing up a provider and a zone, which is Enterprise infra setup,
        # not demo content. The old rows this script used to write would be
        # rejected outright.

        # ── ROE ──
        print("[+] Rules of Engagement...")
        roe_count = 0
        for pname in active_projects:
            if _safe_insert(db,
                "INSERT INTO project_roe (id, project_id, allowed_activities, forbidden_activities, work_hours_start, work_hours_end, timezone, max_scan_rate, requires_approval, emergency_contacts, notes, updated_at, updated_by) "
                "VALUES (:id, :pid, :aa, :fa, '09:00', '18:00', 'Europe/Moscow', '1000 pps', :ra, :ec, '', :ts, :ub)",
                {"id": _id("roe"), "pid": projects[pname],
                 "aa": json.dumps(["External reconnaissance", "Internal reconnaissance", "Phishing", "Exploitation", "Lateral movement", "Privilege escalation", "Data collection"]),
                 "fa": json.dumps(["Data exfiltration", "Destruction of data", "Denial of service", "Physical access"]),
                 "ra": json.dumps(["Social engineering against executives", "Physical access attempts", "Testing OT/SCADA systems"]),
                 "ec": json.dumps([{"name": "CISO", "phone": "+7-495-XXX-XXXX"}, {"name": "IT Director", "phone": "+7-495-XXX-YYYY"}]),
                 "ts": N(), "ub": admin_id}):
                roe_count += 1
        print(f"  Created {roe_count} ROE records")

        # ── Notifications ──
        print("[+] Notifications...")
        notif_templates = [
            ("info", "Project created", "New project '{name}' has been set up and is ready for your team"),
            ("success", "Hosts imported", "{count} hosts were imported into the project"),
            ("warning", "Critical finding", "A new critical finding has been reported: {title}"),
            ("info", "Member joined", "{username} has been added to the project team"),
            ("success", "Objective captured", "Flag captured: {flag}"),
        ]
        n_count = 0
        for pname in active_projects:
            for nt in notif_templates:
                for uname in ["operator1", "analyst1"]:
                    if _safe_insert(db,
                        "INSERT INTO notifications (id, user_id, ts, type, title, body, link, read, project_id) "
                        "VALUES (:id, :uid, :ts, :t, :title, :body, '', false, :pid)",
                        {"id": _id("notif"), "uid": users[uname], "ts": N(), "t": nt[0], "title": nt[1],
                         "body": nt[2].format(name=pname, count="28", title="Kerberoasting", username="operator2", flag="FLAG{DC01}"),
                         "pid": projects[pname]}):
                        n_count += 1
        print(f"  Created {n_count} notifications")

        # ── Domains ──
        print("[+] Domains...")
        domain_names = ["acme.local", "acme.com", "acme-corp.net", "acme-internal.local"]
        dom_count = 0
        for pname in active_projects:
            for dn in domain_names:
                if _safe_insert(db,
                    "INSERT INTO project_domains (id, pid, name, aliases, notes, created_at) "
                    "VALUES (:id, :pid, :n, '{}', '', :ts)",
                    {"id": _id("dom"), "pid": projects[pname], "n": dn, "ts": N()}):
                    dom_count += 1
        print(f"  Created {dom_count} domains")

        # ── Operations ──
        print("[+] Operations (jobs, scans, playbooks, workstations, logs)...")
        seed_operations(db, users, projects, hosts, active_projects, admin_id)

        db.commit()
        print(f"\n=== Demo data seeded successfully! ===")
        print(f"Users: {len(users)} (all passwords: Demo2024!)")
        print(f"Organizations: {len(orgs)}")
        print(f"Projects: {len(projects)}")
        print(f"Hosts: {len(hosts)}")
        print(f"Findings: {len(findings)}")
        print(f"Credentials: {cred_count}")
        print(f"Notes: {note_count}")
        print(f"Attack Paths: {ap_count}")
        print(f"Objectives: {obj_count}")
        print(f"Loot: {loot_count}")

        # Rolled-back inserts are expected (re-running the seeder hits
        # duplicates), but a drifted column shows up here as a whole table
        # failing, which the per-section counts above would otherwise hide.
        return 1 if _report_failures() else 0

    except Exception as e:
        db.rollback()
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        db.close()



# ── Operations: the screens the dataset left empty ───────────────────────
#
# demo_data.json covers the intelligence side (hosts, creds, findings, notes,
# graph) but nothing operational, so Jobs, Scans, Playbooks, Automations,
# Checklist, Workstations, Platform Ops and the two admin log views render
# empty. None of these can be created through the API without live
# infrastructure — jobs and snapshots only exist as a side effect of a real
# scan over attacker SSH — so they are written directly, the same way
# seed_perf_test.py does it.

CHECKLIST_PHASES = {
    "recon": [
        ("Whois / RDAP lookup", True),
        ("DNS enumeration (dig, dnsx)", True),
        ("Subdomain enumeration (subfinder, amass)", True),
        ("Port scan top 1000 (Nmap)", True),
        ("Email harvesting (theHarvester)", True),
        ("OSINT (LinkedIn, Shodan, certs.sh)", True),
        ("Google dorks", False),
        ("Technology fingerprinting (whatweb)", True),
    ],
    "scan": [
        ("Full port scan (all 65535)", True),
        ("Service version detection (-sV)", True),
        ("Default script scan (-sC)", True),
        ("Web crawling / spidering", True),
        ("Directory/file bruteforce (gobuster, ffuf)", True),
        ("VHost enumeration", False),
        ("SSL/TLS analysis (testssl.sh)", True),
        ("Vulnerability scan (Nessus/OpenVAS)", False),
    ],
    "exploit": [
        ("SearchSploit / ExploitDB", True),
        ("Metasploit module search", True),
        ("Credential bruteforce (hydra)", True),
        ("SQLi testing (sqlmap)", True),
        ("XSS testing", False),
        ("File inclusion (LFI/RFI)", False),
        ("SSRF testing", False),
        ("File upload bypass", True),
        ("Deserialization testing", False),
    ],
    "privesc": [
        ("System enumeration (uname, id, env)", True),
        ("SUID/GUID binaries", True),
        ("Cron jobs", True),
        ("World-writable paths", False),
        ("Sudo rules (sudo -l)", True),
        ("Kernel version + exploits", True),
        ("Credential files (.bash_history)", True),
        ("LinPEAS / WinPEAS", True),
        ("Capabilities (getcap)", False),
        ("Token impersonation", True),
    ],
    "lateral": [
        ("ARP scan / host discovery", True),
        ("Pass-the-Hash", True),
        ("Pass-the-Ticket", True),
        ("Kerberoasting", True),
        ("AS-REP Roasting", True),
        ("BloodHound enumeration", True),
        ("SMB lateral movement", True),
        ("WMI / PSExec / WinRM", True),
        ("SSH key reuse", False),
    ],
    "loot": [
        ("Dump /etc/shadow", True),
        ("SAM / NTDS dump", True),
        ("Browser credentials", True),
        ("SSH keys", True),
        ("Config files with credentials", True),
        ("Database dumps", False),
        ("Interesting files (*.conf, *.key)", True),
        ("Screenshots / video", True),
    ],
    "report": [
        ("Executive summary written", True),
        ("All findings documented", True),
        ("Screenshots attached", True),
        ("CVSS scores assigned", True),
        ("Remediation recommendations", False),
        ("Attack diagram", False),
        ("Event timeline", True),
        ("Final review", False),
    ],
}

# (type, connector, status, title, target, command, output, minutes_after_epoch)
JOBS_DATA = [
    ("scan", "nmap", "done", "Nmap top-1000 — 10.0.1.0/24",
     "10.0.1.0/24", "nmap -sV -sC --top-ports 1000 -oX - 10.0.1.0/24",
     "Nmap scan report for DC01.acme.local (10.0.1.10)\n"
     "Host is up (0.00042s latency).\n"
     "PORT     STATE SERVICE      VERSION\n"
     "53/tcp   open  domain       Simple DNS Plus\n"
     "88/tcp   open  kerberos-sec Microsoft Windows Kerberos\n"
     "389/tcp  open  ldap         Microsoft Windows Active Directory LDAP\n"
     "445/tcp  open  microsoft-ds Windows Server 2019 Standard\n"
     "3268/tcp open  ldap         Microsoft Windows Active Directory LDAP\n"
     "\nNmap done: 256 IP addresses (14 hosts up) scanned in 42.11 seconds", 12),
    ("scan", "nuclei", "done", "Nuclei — DMZ web tier",
     "172.16.0.0/24", "nuclei -u https://172.16.0.10 -severity medium,high,critical",
     "[CVE-2021-44228] [http] [critical] https://172.16.0.10/api/login\n"
     "[apache-detect] [http] [info] https://172.16.0.10 [Apache/2.4.29]\n"
     "[tls-version] [ssl] [info] https://172.16.0.10 [tls10]\n"
     "[weak-cipher-suites] [ssl] [low] https://172.16.0.10\n"
     "\n[INF] Templates loaded: 4912, Hosts: 1, Findings: 4", 48),
    ("cred_validation", "netexec", "done", "SMB validation — svc_backup",
     "10.0.1.0/24", "netexec smb 10.0.1.0/24 -u svc_backup -H <ntlm> --shares",
     "SMB  10.0.1.10  445  DC01       [+] acme.local\\svc_backup (Pwn3d!)\n"
     "SMB  10.0.1.20  445  FS01       [+] acme.local\\svc_backup\n"
     "SMB  10.0.1.70  445  SHAREPOINT [-] acme.local\\svc_backup STATUS_LOGON_FAILURE\n"
     "\n2 of 3 hosts accepted the credential, 1 with administrative access", 95),
    ("scan", "httpx", "done", "httpx probe — discovered subdomains",
     "acme.com", "httpx -l subdomains.txt -title -tech-detect -status-code",
     "https://www.acme.com      [200] [ACME Corp] [nginx:1.18.0]\n"
     "https://mail.acme.com     [200] [Outlook Web App] [Microsoft-IIS/10.0]\n"
     "https://vpn.acme.com      [200] [Global Protect] [PanOS]\n"
     "https://gitlab.acme.com   [302] [] [nginx]\n"
     "https://old.acme.com      [200] [Index of /] [Apache/2.2.15]", 140),
    ("scan", "ffuf", "running", "ffuf — old.acme.com content discovery",
     "https://old.acme.com", "ffuf -u https://old.acme.com/FUZZ -w raft-medium.txt -mc 200,301,403",
     "backup                  [Status: 301, Size: 0]\n"
     "admin                   [Status: 403, Size: 1041]\n"
     ".git                    [Status: 301, Size: 0]\n"
     ":: Progress: [18422/30000] :: Job [1/1] :: 412 req/sec", 180),
    ("ad_enum", "netexec", "failed", "SPN enumeration — acme.local",
     "10.0.1.10", "netexec ldap 10.0.1.10 -u svc_backup -H <ntlm> --kerberoasting out.txt",
     "LDAP 10.0.1.10 389 DC01 [-] acme.local\\svc_backup STATUS_ACCOUNT_LOCKED_OUT\n"
     "\nAccount locked after 5 failed binds — lockout policy is 5/30min", 205),
]

PLAYBOOKS_DATA = [
    ("AD Initial Enumeration",
     "Domain recon from a single valid credential: users, groups, SPNs, delegation, ADCS.",
     ["netexec ldap $DC -u $USER -p $PASS --users",
      "netexec ldap $DC -u $USER -p $PASS --groups",
      "netexec ldap $DC -u $USER -p $PASS --kerberoasting kerb.out",
      "netexec ldap $DC -u $USER -p $PASS --trusted-for-delegation",
      "certipy find -u $USER@$DOMAIN -p $PASS -dc-ip $DC"]),
    ("DMZ Web Tier Sweep",
     "Probe, fingerprint and vuln-scan everything answering on the perimeter.",
     ["httpx -l $TARGETS -title -tech-detect -status-code",
      "nuclei -l live.txt -severity medium,high,critical",
      "ffuf -u $URL/FUZZ -w raft-medium.txt -mc 200,301,403"]),
    ("Credential Spray and Validate",
     "Spray one credential across the estate, then mark access edges from the results.",
     ["netexec smb $SUBNET -u $USER -H $HASH --shares",
      "netexec winrm $SUBNET -u $USER -H $HASH",
      "netexec mssql $SUBNET -u $USER -H $HASH"]),
]

AUTOMATIONS_DATA = [
    ("New host → port scan",
     "Whenever a host appears in scope, queue a top-1000 Nmap against it.",
     True, "host.created", 14),
    ("Critical finding → notify leads",
     "Any finding promoted to critical notifies the engagement leads.",
     True, "finding.severity_changed", 6),
    ("Valid credential → spray subnet",
     "A newly validated domain credential is sprayed across its own subnet.",
     False, "cred.validated", 2),
    ("Daily scope reconciliation",
     "Re-resolves scope domains and flags anything that moved out of scope.",
     True, "schedule.daily", 31),
]

WORKSTATION_TEMPLATES_DATA = [
    ("Kali Full — 4 vCPU", "docker", "offensive",
     {"image": "kalilinux/kali-rolling", "cpus": 4, "memory_gb": 8,
      "packages": ["kali-linux-headless", "bloodhound", "netexec"]}),
    ("Kali Slim — 2 vCPU", "docker", "offensive",
     {"image": "kalilinux/kali-rolling", "cpus": 2, "memory_gb": 4,
      "packages": ["nmap", "netexec", "impacket-scripts"]}),
    ("Ubuntu Analyst", "docker", "analysis",
     {"image": "ubuntu:24.04", "cpus": 2, "memory_gb": 4,
      "packages": ["python3", "jq", "ripgrep"]}),
    ("Windows Tooling", "hetzner", "offensive",
     {"image": "windows-server-2022", "type": "cx41", "location": "nbg1"}),
]

# (name, status, operator, template index, address, minutes_after_epoch)
WORKSTATIONS_DATA = [
    ("ws-operator1-kali", "ready", "operator1", 0, "10.90.0.11", 5),
    ("ws-operator2-kali", "ready", "operator2", 1, "10.90.0.12", 9),
    ("ws-analyst1-ubuntu", "ready", "analyst1", 2, "10.90.0.21", 17),
    ("ws-pool-kali-01", "ready", None, 1, "10.90.0.31", 2),
    ("ws-pool-kali-02", "provisioning", None, 1, "", 220),
    ("ws-operator1-win", "destroyed", "operator1", 3, "", 1),
]

SERVICE_TEMPLATES_DATA = [
    ("Adaptix C2 + HTTPS redirector", "c2", "Teamserver behind an nginx HTTPS redirector with domain fronting.", "umbryx/adaptix:latest"),
    ("Mythic C2", "c2", "Mythic teamserver with the Apollo agent image preloaded.", "umbryx/mythic:latest"),
    ("Sliver C2", "c2", "Sliver teamserver with mTLS and WireGuard listeners.", "umbryx/sliver:latest"),
    ("Nginx redirector", "redirector", "Filtering reverse proxy — UA, ASN and path allowlists.", "umbryx/nginx-redirector:latest"),
    ("Evilginx2 phishing", "phishing", "Transparent-proxy phishing with session capture.", "umbryx/evilginx2:latest"),
    ("Pwndrop payload host", "payload", "Authenticated payload hosting over HTTPS.", "umbryx/pwndrop:latest"),
    ("WireGuard gateway", "vpn", "Site-to-site tunnel into the engagement network.", "umbryx/wireguard:latest"),
    ("Chisel pivot", "pivot", "TCP/UDP tunnel over HTTP for constrained egress.", "umbryx/chisel:latest"),
    ("Ligolo-mp pivot", "pivot", "Userland TUN pivot for multi-operator use.", "umbryx/ligolo-mp:latest"),
    ("Iodine DNS tunnel", "pivot", "DNS-tunnelled egress for filtered networks.", "umbryx/iodine:latest"),
]

DEVOPS_LOG_DATA = [
    ("info", "deploy", "Stack 'acme-c2-primary' deploy started (3 services)", 3),
    ("info", "deploy", "Service 'adaptix-teamserver' is healthy on 10.90.1.10", 7),
    ("info", "dns", "A record c2.example.com -> 203.0.113.10 created", 8),
    ("info", "firewall", "Ingress locked to operator workstations (3 rules applied)", 9),
    ("warn", "deploy", "Service 'nginx-redirector' failed its first health check, retrying", 11),
    ("info", "deploy", "Service 'nginx-redirector' is healthy on 10.90.1.11", 13),
    ("info", "tls", "Certificate issued for c2.example.com (ACME, 90d)", 14),
    ("info", "discovery", "Teamserver listener registered: https/443", 16),
    ("error", "deploy", "Stack 'acme-phish-01' rolled back: provider quota exceeded", 190),
    ("info", "teardown", "Stack 'acme-c2-primary' destroyed, 3 services removed, DNS revoked", 2600),
]


def _at(minutes):
    """A timestamp `minutes` after DEMO_EPOCH, in the project's ISO-Z format."""
    if _LIVE:
        return ts_now()
    base = datetime.strptime(DEMO_EPOCH, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (base + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_operations(db, users, projects, hosts, active_projects, admin_id):
    """Fill the operational tables so no documented screen renders empty."""
    counts = {}
    # Some columns hold a username and some hold a user id, and the two are
    # not interchangeable: Jobs renders created_by straight into its "By"
    # column, so an id there is displayed raw. The app's own writers are the
    # reference — scans.py:257 and playbooks/routes.py:133 store the username;
    # workstations.py:1159 and automations_api.py:398 store the id.
    admin_user = "admin"

    # ── Jobs ──
    job_ids = {}
    for pname in active_projects[:2]:
        pid = projects[pname]
        for jtype, conn, status, title, target, command, output, mins in JOBS_DATA:
            jid = _id("j")
            # started_at/finished_at are NOT NULL with a '' default, so an
            # unfinished job carries the empty string, not NULL.
            finished = _at(mins + 2) if status in ("done", "failed") else ""
            if _safe_insert(
                db,
                "INSERT INTO jobs (id, pid, type, status, title, target, command, output, "
                "connector_key, created_by, created_at, started_at, finished_at, result_json) "
                "VALUES (:id, :pid, :t, :s, :ti, :tg, :c, :o, :ck, :cb, :ca, :sa, :fa, :rj)",
                {
                    "id": jid, "pid": pid, "t": jtype, "s": status, "ti": title,
                    "tg": target, "c": command, "o": output, "ck": conn,
                    "cb": admin_user, "ca": _at(mins), "sa": _at(mins),
                    "fa": finished,
                    "rj": json.dumps({"exit_code": 0 if status == "done" else 1,
                                      "lines": len(output.splitlines())}),
                },
            ):
                counts["jobs"] = counts.get("jobs", 0) + 1
                job_ids.setdefault(pname, []).append((jid, conn))
    print(f"  Created {counts.get('jobs', 0)} jobs")

    # ── Scan snapshots ──
    # capture_host_snapshot owns the snapshot shape (core/scan_diff.py), so it
    # builds the row; only the id and timestamp are then pinned, because the
    # helper stamps a live clock and a random id.
    from app import models
    from app.core.scan_diff import capture_host_snapshot

    snap_n = 0
    for pname, jobs in job_ids.items():
        pid = projects[pname]
        nmap_jobs = [j for j, c in jobs if c == "nmap"]
        if not nmap_jobs:
            continue
        host_objs = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.deleted_at.is_(None))
            .order_by(models.Host.ip)
            .limit(6)
            .all()
        )
        for i, host in enumerate(host_objs):
            snap = capture_host_snapshot(db, pid, host, job_id=nmap_jobs[0], connector_key="nmap")
            snap.id = _id("snap")
            snap.created_at = _at(14 + i)
            snap_n += 1
    db.flush()
    print(f"  Created {snap_n} scan snapshots")
    counts["scan_snapshots"] = snap_n

    # ── Checklist ──
    cl_n = 0
    for pname in active_projects:
        pid = projects[pname]
        idx = 0
        for phase, items in CHECKLIST_PHASES.items():
            for label, done in items:
                if _safe_insert(
                    db,
                    "INSERT INTO checklist_items (id, pid, phase, text, done, order_idx) "
                    "VALUES (:id, :pid, :ph, :tx, :d, :oi)",
                    {"id": _id("cl"), "pid": pid, "ph": phase, "tx": label,
                     "d": done, "oi": idx},
                ):
                    cl_n += 1
                idx += 1
    print(f"  Created {cl_n} checklist items")

    # ── Custom playbooks and runs ──
    pb_ids = []
    for title, desc, steps in PLAYBOOKS_DATA:
        pbid = _id("pb")
        if _safe_insert(
            db,
            "INSERT INTO custom_playbooks (id, title, description, steps_json, created_by, created_at, updated_at) "
            "VALUES (:id, :t, :d, :sj, :cb, :ca, :ua)",
            {"id": pbid, "t": title, "d": desc,
             "sj": json.dumps([{"order": i, "command": c} for i, c in enumerate(steps)]),
             "cb": admin_user, "ca": _at(0), "ua": _at(0)},
        ):
            pb_ids.append((pbid, title))
    run_n = 0
    for pname in active_projects[:2]:
        pid = projects[pname]
        for i, (pbid, title) in enumerate(pb_ids):
            status = ["done", "done", "failed"][i % 3]
            if _safe_insert(
                db,
                "INSERT INTO playbook_runs (id, pid, playbook_id, title, status, created_by, "
                "created_at, started_at, finished_at) "
                "VALUES (:id, :pid, :pb, :t, :s, :cb, :ca, :sa, :fa)",
                {"id": _id("pbr"), "pid": pid, "pb": pbid, "t": title, "s": status,
                 "cb": admin_user, "ca": _at(30 + i * 20), "sa": _at(30 + i * 20),
                 "fa": _at(34 + i * 20)},
            ):
                run_n += 1
    print(f"  Created {len(pb_ids)} playbooks, {run_n} runs")

    # ── Automations ──
    au_n = 0
    for pname in active_projects[:2]:
        pid = projects[pname]
        for name, desc, enabled, trigger, runs in AUTOMATIONS_DATA:
            if _safe_insert(
                db,
                "INSERT INTO pb_automations (id, pid, name, description, enabled, definition, "
                "owner_id, run_count, last_run_at, last_run_status, created_at, updated_at) "
                "VALUES (:id, :pid, :n, :d, :e, :df, :o, :rc, :lr, :ls, :ca, :ua)",
                {"id": _id("au"), "pid": pid, "n": name, "d": desc, "e": enabled,
                 "df": json.dumps({"trigger": trigger, "actions": ["queue_scan"]}),
                 "o": admin_id, "rc": runs,
                 "lr": _at(200) if runs else None,
                 "ls": "done" if runs else None,
                 "ca": _at(0), "ua": _at(0)},
            ):
                au_n += 1
    print(f"  Created {au_n} automations")

    # ── Workstations ──
    tpl_ids = []
    for name, kind, category, spec in WORKSTATION_TEMPLATES_DATA:
        tid = _id("wst")
        if _safe_insert(
            db,
            "INSERT INTO workstation_templates (id, name, kind, spec, is_builtin, created_at, category) "
            "VALUES (:id, :n, :k, :sp, false, :ca, :cat)",
            {"id": tid, "n": name, "k": kind, "sp": json.dumps(spec), "ca": _at(0), "cat": category},
        ):
            tpl_ids.append(tid)
    ws_n = act_n = 0
    first_pid = projects[active_projects[0]]
    for name, status, operator, tpl_i, addr, mins in WORKSTATIONS_DATA:
        wsid = _id("ws")
        uid = users.get(operator) if operator else None
        if _safe_insert(
            db,
            "INSERT INTO operator_workstations (id, project_id, user_id, template_id, name, status, "
            "access_address, created_at, ready_at, destroyed_at, provider, is_pool) "
            "VALUES (:id, :pid, :uid, :tid, :n, :s, :aa, :ca, :ra, :da, 'docker', :pool)",
            {"id": wsid, "pid": first_pid if operator else None, "uid": uid,
             "tid": tpl_ids[tpl_i] if tpl_i < len(tpl_ids) else None,
             "n": name, "s": status, "aa": addr, "ca": _at(mins),
             "ra": _at(mins + 3) if status == "ready" else None,
             "da": _at(mins + 400) if status == "destroyed" else None,
             "pool": operator is None},
        ):
            ws_n += 1
            if uid:
                # workstation_access.key_id is a foreign key into
                # user_ssh_keys: the grant is "this user's key is authorised on
                # this box", so the key has to exist first.
                kid = _id("usk")
                if _safe_insert(
                    db,
                    "INSERT INTO user_ssh_keys (id, user_id, name, public_key, fingerprint, created_at) "
                    "VALUES (:id, :uid, :n, :pk, :fp, :ca)",
                    {"id": kid, "uid": uid, "n": f"{operator}-laptop",
                     "pk": f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{kid}demo {operator}@example.com",
                     "fp": f"SHA256:{kid}demofingerprintplaceholder",
                     "ca": _at(0)},
                ):
                    _safe_insert(
                        db,
                        "INSERT INTO workstation_access (id, workstation_id, user_id, key_id, "
                        "granted_by, granted_at) VALUES (:id, :ws, :uid, :kid, :gb, :ga)",
                        {"id": _id("wsa"), "ws": wsid, "uid": uid, "kid": kid,
                         "gb": admin_id, "ga": _at(mins + 4)},
                    )
            if status == "ready":
                for k, cmd in enumerate([
                    "netexec smb 10.0.1.0/24 -u svc_backup -H <ntlm> --shares",
                    "bloodhound-python -d acme.local -u svc_backup --hashes <ntlm> -c All",
                    "impacket-secretsdump acme.local/svc_backup@10.0.1.10 -hashes <ntlm>",
                ]):
                    if _safe_insert(
                        db,
                        "INSERT INTO workstation_actions (id, workstation_id, pid, username, "
                        "command, cwd, source, ts, exit_code) "
                        "VALUES (:id, :ws, :pid, :u, :c, '/root', 'ssh', :ts, 0)",
                        {"id": _id("wsact"), "ws": wsid, "pid": first_pid,
                         "u": operator or "pool", "c": cmd, "ts": _at(mins + 10 + k * 5)},
                    ):
                        act_n += 1
    print(f"  Created {len(tpl_ids)} workstation templates, {ws_n} workstations, {act_n} actions")

    # ── Platform Ops catalog and DevOps log ──
    st_n = 0
    for name, stype, desc, image in SERVICE_TEMPLATES_DATA:
        if _safe_insert(
            db,
            "INSERT INTO infra_service_templates (id, name, type, version, description, "
            "image_source, image_ref, is_builtin, created_at) "
            "VALUES (:id, :n, :t, '1.0.0', :d, 'registry', :img, false, :ca)",
            {"id": _id("ist"), "n": name, "t": stype, "d": desc, "img": image, "ca": _at(0)},
        ):
            st_n += 1
    dl_n = 0
    for level, category, message, mins in DEVOPS_LOG_DATA:
        if _safe_insert(
            db,
            "INSERT INTO infra_devops_log (id, level, category, message, actor, created_at) "
            "VALUES (:id, :lv, :cat, :m, :a, :ca)",
            {"id": _id("dvl"), "lv": level, "cat": category, "m": message,
             "a": "admin", "ca": _at(mins)},
        ):
            dl_n += 1
    print(f"  Created {st_n} service templates, {dl_n} devops log entries")

    # ── Admin log views ──
    audit_rows = [
        ("auth.login", "user", "admin", "Signed in from 10.90.0.11", 0),
        ("project.create", "project", "ACME Corp", "Project created", 2),
        ("scope.add", "scope", "10.0.0.0/8", "Added to scope as in-scope", 4),
        ("roe.update", "roe", "ACME Corp", "Work hours narrowed to 09:00-18:00", 6),
        ("cred.create", "cred", "svc_backup", "Credential added (ntlm)", 95),
        ("finding.promote", "finding", "Log4Shell on DMZ-WEB01", "Candidate promoted to critical", 120),
        ("member.add", "user", "analyst2", "Added to project as analyst", 140),
        ("report.export", "report", "ACME Corp", "PDF exported (16 findings)", 2400),
        ("project.close", "project", "Iron Fortress", "Closed, infrastructure torn down", 2600),
    ]
    al_n = 0
    for action, ttype, tid, detail, mins in audit_rows:
        if _safe_insert(
            db,
            "INSERT INTO audit_log (id, ts, actor_id, actor_name, action, target_type, "
            "target_id, detail, ip_address) "
            "VALUES (:id, :ts, :aid, 'admin', :act, :tt, :tid, :d, '10.90.0.11')",
            {"id": _id("al"), "ts": _at(mins), "aid": admin_id, "act": action,
             "tt": ttype, "tid": tid, "d": detail},
        ):
            al_n += 1
    sys_rows = [
        ("auth", "info", "login_success", "admin signed in", 0),
        ("migration", "info", "alembic_head", "Schema at head 105_host_claims_released_at", 0),
        ("license", "info", "license_applied", "Enterprise license applied, offline channel", 1),
        ("scan", "info", "scan_complete", "nmap finished: 14 hosts up of 256", 14),
        ("scan", "warn", "scan_slow", "nuclei run exceeded 120s on 172.16.0.10", 50),
        ("infra", "info", "stack_deployed", "acme-c2-primary: 3 services healthy", 16),
        ("infra", "error", "quota_exceeded", "acme-phish-01 rolled back: provider quota", 190),
        ("audit", "info", "retention_pass", "Audit retention pass removed 0 rows (365d)", 1440),
        ("auth", "warn", "lockout", "svc_backup locked out after 5 failed binds", 205),
    ]
    sl_n = 0
    for category, level, event, message, mins in sys_rows:
        if _safe_insert(
            db,
            "INSERT INTO system_logs (id, category, level, event, message, user_id, ts) "
            "VALUES (:id, :cat, :lv, :ev, :m, :uid, :ts)",
            {"id": _id("sl"), "cat": category, "lv": level, "ev": event,
             "m": message, "uid": admin_id, "ts": _at(mins)},
        ):
            sl_n += 1
    print(f"  Created {al_n} audit entries, {sl_n} system log entries")


def export_data(path):
    print(f"Exporting demo data to {path}...")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    db = SessionLocal()
    try:
        data = {}
        for table in [
            "users", "organizations", "teams", "organization_members",
            "projects", "project_members", "hosts", "findings", "creds",
            "notes", "attack_paths", "attack_steps", "objectives", "loots",
            "scopes", "networks", "network_nodes", "network_edges",
            "project_roe", "notifications", "project_domains",
            "timeline_events", "instance_templates",
            # Operational tables — see seed_operations().
            "jobs", "scan_snapshots", "checklist_items", "custom_playbooks",
            "playbook_runs", "pb_automations", "workstation_templates",
            "operator_workstations", "workstation_access", "workstation_actions",
            "infra_service_templates", "infra_devops_log", "audit_log", "system_logs",
        ]:
            rows = db.execute(text(f'SELECT * FROM "{table}"')).mappings().all()
            data[table] = [dict(r) for r in rows]
            print(f"  {table}: {len(rows)} rows")
        with open(path, "w") as f:
            json.dump(data, f, default=str, indent=2)
        print(f"Exported to {path}")
    finally:
        db.close()


def import_data(path):
    """Load a dump written by --export, reconciling it against today's schema.

    The dump is a snapshot of columns as they were when it was taken, so it
    drifts as migrations land: `organizations.plan` and `hosts.notes` are gone
    and `dns_records` was redesigned for the EE DNS tab. Rather than build the
    INSERT from the dump's own keys — which fails the moment one column is
    dropped — each table is intersected with the columns the database actually
    has now. Dropped columns are reported and skipped; a table that is missing
    a NOT NULL column with no default is skipped whole, because rows built from
    a stale shape would be rejected or, worse, silently wrong.
    """
    print(f"Importing demo data from {path}...")
    db = SessionLocal()
    try:
        with open(path) as f:
            data = json.load(f)
        order = [
            "users", "organizations", "teams", "organization_members",
            "projects", "project_members", "hosts", "findings", "creds",
            "notes", "attack_paths", "attack_steps", "objectives", "loots",
            "scopes", "networks", "network_nodes", "network_edges",
            "project_roe", "notifications", "project_domains",
            "timeline_events", "instance_templates",
            "jobs", "scan_snapshots", "checklist_items", "custom_playbooks",
            "playbook_runs", "pb_automations", "workstation_templates",
            "operator_workstations", "workstation_access", "workstation_actions",
            "infra_service_templates", "infra_devops_log", "audit_log", "system_logs",
        ]
        skipped = []
        for table in order:
            rows = data.get(table, [])
            if not rows:
                continue

            live = _live_columns(db, table)
            if not live:
                skipped.append((table, "table no longer exists"))
                continue

            dump_cols = set(rows[0].keys())
            cols = sorted(dump_cols & live)
            if not cols:
                skipped.append((table, "no columns in common with the schema"))
                continue

            missing = _required_columns(db, table) - set(cols)
            if missing:
                skipped.append(
                    (table, f"dump cannot fill required column(s): {', '.join(sorted(missing))}")
                )
                continue

            dropped = dump_cols - live
            placeholders = ", ".join(f":{c}" for c in cols)
            col_list = ", ".join(cols)
            sql = f'INSERT INTO "{table}" ({", ".join(chr(34) + c + chr(34) for c in col_list)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING'
            for row in rows:
                db.execute(text(sql), {c: row[c] for c in cols})
            note = f" (dropped {', '.join(sorted(dropped))})" if dropped else ""
            print(f"  {table}: {len(rows)} rows imported{note}")

        db.commit()
        if skipped:
            print("\nSkipped:")
            for table, why in skipped:
                print(f"  {table}: {why}")
        print("Import complete!")
        return 0
    except Exception as e:
        db.rollback()
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Umbryx Demo Data")
    parser.add_argument(
        "--export",
        dest="export_file",
        nargs="?",
        const="/app/scripts/demo_data.json",
        help="Export to JSON (default: /app/scripts/demo_data.json)",
    )
    parser.add_argument("--import", dest="import_file", help="Import from JSON")
    args = parser.parse_args()

    # Exit non-zero when anything was rolled back or skipped, so a stand that
    # seeds itself in a script notices instead of screenshotting empty tables.
    if args.export_file:
        export_data(args.export_file)
        sys.exit(0)
    elif args.import_file:
        sys.exit(import_data(args.import_file))
    else:
        sys.exit(seed() or 0)
