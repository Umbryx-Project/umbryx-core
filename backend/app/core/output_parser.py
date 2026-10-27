"""
Auto-enrichment: detect tool from command, parse output, return structured host data.

Supported tools:
  nmap      — text output ("Nmap scan report for ...") or XML ("-oX -")
  netexec   — CME/nxc/netexec SMB/WinRM/LDAP/RDP output
  secretsdump — impacket secretsdump NTLM hashes
  hydra     — hydra/medusa/crowbar found credentials
"""

import re
import xml.etree.ElementTree as ET

# ── Tool detection ────────────────────────────────────────────────────

_TOOL_PATTERNS = [
    ("nmap", re.compile(r"\bnmap\b", re.I)),
    ("netexec", re.compile(r"\b(netexec|nxc|crackmapexec|cme)\b", re.I)),
    ("secretsdump", re.compile(r"\bsecretsdump\b|\bimpacket-secretsdump\b", re.I)),
    ("hydra", re.compile(r"\b(hydra|medusa|crowbar)\b", re.I)),
    # impacket family (termtrack, 2026-10-13): the tools operators actually
    # fill a project with. Connection strings carry the credentials —
    # parsed, but the secret material never leaves the parser output for
    # auto-apply (see termtrack/observations.py mapping).
    ("getuserspns", re.compile(r"\bGetUserSPNs(\.py)?\b", re.I)),
    ("getnpusers", re.compile(r"\bGetNPUsers(\.py)?\b", re.I)),
    ("ntlmrelayx", re.compile(r"\bntlmrelayx(\.py)?\b", re.I)),
    ("psexec_family", re.compile(r"\b(psexec|smbexec|wmiexec|atexec)(\.py)?\b", re.I)),
    ("responder", re.compile(r"\bresponder\b", re.I)),
    ("smbclient", re.compile(r"\bsmbclient\b", re.I)),
    ("whatweb", re.compile(r"\bwhatweb\b", re.I)),
]


def detect_tool(command: str) -> str | None:
    for name, pat in _TOOL_PATTERNS:
        if pat.search(command):
            return name
    return None


# ── Nmap parsers ──────────────────────────────────────────────────────


def _nmap_xml_get_hostname(host_el) -> str:
    for hn in host_el.findall(".//hostname"):
        if hn.get("type") in ("user", "PTR", None):
            return hn.get("name", "")
    return ""


def _nmap_xml_get_os(host_el) -> str:
    os_el = host_el.find(".//osmatch")
    return os_el.get("name", "") if os_el is not None else ""


def _nmap_xml_get_ports(host_el) -> tuple[list, list]:
    ports, services = [], []
    for port_el in host_el.findall(".//port"):
        st = port_el.find("state")
        if st is None or st.get("state") != "open":
            continue
        portid = port_el.get("portid", "")
        proto = port_el.get("protocol", "tcp")
        svc_el = port_el.find("service")
        svc_name = svc_el.get("name", "") if svc_el is not None else ""
        svc_product = svc_el.get("product", "") if svc_el is not None else ""
        ports.append(f"{portid}/{proto}")
        if svc_name:
            label = f"{portid}/{svc_name}" + (f" ({svc_product})" if svc_product else "")
            services.append(label)
    return ports, services


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is None or state_el.get("state") != "up":
            continue
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue
        ports, services = _nmap_xml_get_ports(host_el)
        hosts.append(
            {
                "ip": ip,
                "hostname": _nmap_xml_get_hostname(host_el),
                "os": _nmap_xml_get_os(host_el),
                "ports": ports,
                "services": services,
            }
        )
    return hosts


def _nmap_text_parse_host_line(line: str) -> dict | None:
    m = re.match(r"Nmap scan report for (?:(\S+)\s+\((\d[\d.]+)\)|(\d[\d.]+))", line)
    if not m:
        return None
    if m.group(3):
        return {"ip": m.group(3), "hostname": "", "os": "", "ports": [], "services": []}
    return {"ip": m.group(2), "hostname": m.group(1), "os": "", "ports": [], "services": []}


def _nmap_text_try_os(line: str, current: dict) -> bool:
    m = re.match(r"OS details?: (.+)", line, re.I)
    if m and not current["os"]:
        current["os"] = m.group(1).strip()
        return True
    m = re.match(r"Aggressive OS guesses?: (.+?) \(\d", line, re.I)
    if m and not current["os"]:
        current["os"] = m.group(1).strip()
        return True
    return False


def _nmap_text_try_port(line: str, current: dict) -> None:
    m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S*)(.*)", line, re.I)
    if not m:
        return
    port, proto, svc, rest = m.groups()
    port_str = f"{port}/{proto}"
    if port_str not in current["ports"]:
        current["ports"].append(port_str)
    svc = svc.strip()
    version = rest.strip()
    if svc:
        label = f"{port}/{svc}" + (f" ({version})" if version else "")
        current["services"].append(label)


def _parse_nmap_text(text: str) -> list[dict]:
    hosts = []
    current: dict | None = None
    for line in text.splitlines():
        line = line.strip()
        host = _nmap_text_parse_host_line(line)
        if host is not None:
            if current:
                hosts.append(current)
            current = host
            continue
        if current is None:
            continue
        if _nmap_text_try_os(line, current):
            continue
        _nmap_text_try_port(line, current)
    if current:
        hosts.append(current)
    return hosts


def parse_nmap(output: str) -> list[dict]:
    # Try XML first (if command used -oX -)
    if output.lstrip().startswith("<?xml") or output.lstrip().startswith("<nmaprun"):
        return _parse_nmap_xml(output)
    return _parse_nmap_text(output)


# ── NetExec / CME parser ──────────────────────────────────────────────

_NXC_HOST_RE = re.compile(
    r"^(?:SMB|WINRM|LDAP|RDP|FTP|SSH|MSSQL)\s+([\d.]+)\s+(\d+)\s+(\S+)\s+\[", re.I
)
_NXC_WIN_OS_RE = re.compile(r"(Windows\s+\S+(?:\s+\S+)?)", re.I)
_NXC_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.I)
_NXC_PWNED_RE = re.compile(r"\(Pwn3d!\)", re.I)
_NXC_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}$")


def _nxc_update_host(line: str, m, hosts: dict) -> None:
    ip, port, name = m.group(1), m.group(2), m.group(3)
    if ip not in hosts:
        hosts[ip] = {
            "ip": ip,
            "hostname": name,
            "domain": "",
            "ports": [],
            "services": [],
            "os": "",
            "smb_signing": None,
        }
    h = hosts[ip]
    port_str = f"{port}/tcp"
    if port_str not in h["ports"]:
        h["ports"].append(port_str)
    dm = _NXC_DOMAIN_RE.search(line)
    if dm:
        domain = dm.group(1).strip()
        if domain.lower() != name.lower():
            h["domain"] = domain
    om = _NXC_WIN_OS_RE.search(line)
    if om and not h["os"]:
        h["os"] = om.group(1).strip()
    sm = re.search(r"\(signing:(True|False)\)", line, re.I)
    if sm:
        h["smb_signing"] = sm.group(1).lower() == "true"


def _nxc_collect_cred(line: str, found_creds: list) -> None:
    if "[+]" not in line or ":" not in line:
        return
    tail = line.split("[+]", 1)[1].strip()
    left, sep, remainder = tail.partition(":")
    if not sep:
        return
    account = left.strip().split()[-1] if left.strip() else ""
    secret = remainder.strip().split()[0] if remainder.strip() else ""
    domain_part = ""
    username = account
    if "\\" in account:
        domain_part, username = account.split("\\", 1)
    username = username.strip()
    domain_part = domain_part.strip()
    if username and secret and secret not in ("<empty>", ""):
        ctype = "hash" if _NXC_HASH_RE.match(secret) else "plain"
        pwned = bool(_NXC_PWNED_RE.search(line))
        found_creds.append(
            {
                "domain": domain_part,
                "username": username,
                "secret": secret,
                "type": ctype,
                "service": "smb",
                "pwned": pwned,
            }
        )


def parse_netexec(output: str) -> dict:
    hosts: dict[str, dict] = {}
    found_creds: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _NXC_HOST_RE.match(line)
        if m:
            _nxc_update_host(line, m, hosts)
            continue
        if "[+]" in line:
            _nxc_collect_cred(line, found_creds)
    return {"hosts": list(hosts.values()), "creds": found_creds}


# ── Secretsdump parser ────────────────────────────────────────────────

_HASH_LINE_RE = re.compile(
    r"^(?:([\w.-]+)\\)?([\w.$@-]+):\d+:([A-Fa-f0-9]{32}):([A-Fa-f0-9]{32}):::",
)


def parse_secretsdump(output: str) -> dict:
    creds = []
    for line in output.splitlines():
        line = line.strip()
        m = _HASH_LINE_RE.match(line)
        if m:
            domain, username, lm, nt = m.groups()
            creds.append(
                {
                    "domain": domain or "",
                    "username": username,
                    "secret": f"{lm}:{nt}",
                    "type": "ntlm",
                    "service": "smb",
                }
            )
    return {"creds": creds}


def parse_hydra(output: str) -> dict:
    medusa_user_marker = "User:"
    medusa_password_marker = "Password:"
    hydra_login_marker = "login:"
    hydra_password_marker = "password:"
    creds = []
    for line in output.splitlines():
        line = line.strip()
        if (
            line.startswith("[")
            and "] host:" in line
            and hydra_login_marker in line
            and hydra_password_marker in line
        ):
            parts = line.split()
            service = parts[1].strip("[]") if len(parts) > 1 else ""
            ip = line.split("host:", 1)[1].split(hydra_login_marker, 1)[0].strip().split()[0]
            username = (
                line.split(hydra_login_marker, 1)[1]
                .split(hydra_password_marker, 1)[0]
                .strip()
                .split()[0]
            )
            secret = line.split(hydra_password_marker, 1)[1].strip().split()[0]
            creds.append(
                {
                    "host": ip,
                    "username": username,
                    "secret": secret,
                    "type": "plain",
                    "service": service,
                }
            )
        if (
            "ACCOUNT FOUND" in line
            and "Host:" in line
            and medusa_user_marker in line
            and medusa_password_marker in line
        ):
            ip = line.split("Host:", 1)[1].split(medusa_user_marker, 1)[0].strip().split()[0]
            username = (
                line.split(medusa_user_marker, 1)[1]
                .split(medusa_password_marker, 1)[0]
                .strip()
                .split()[0]
            )
            secret = line.split(medusa_password_marker, 1)[1].strip().split()[0]
            creds.append(
                {
                    "host": ip,
                    "username": username,
                    "secret": secret,
                    "type": "plain",
                    "service": "unknown",
                }
            )
    return {"creds": creds}


# ── Main entry ────────────────────────────────────────────────────────


def parse_output(command: str, output: str) -> dict:
    """Detect tool from command and parse output.

    Returns:
        {
          "tool": str | None,
          "hosts": [{"ip", "hostname", "os", "domain", "ports", "services", ...}],
          "creds": [{"domain", "username", "secret", "type", "service", ...}],
          # network-level facts (interfaces, routes, subnets) — context,
          # not host rows; consumers turn them into observations
          "network": [{"kind": "iface|route", ...}],
          "dns": [{"name", "type", "value"}],
        }
    """
    tool = detect_tool(command)
    if not tool or not output:
        return {"tool": tool, "hosts": [], "creds": [], "network": [], "dns": []}

    if tool == "nmap":
        hosts = parse_nmap(output)
        return {"tool": "nmap", "hosts": hosts, "creds": [], "network": [], "dns": []}

    if tool == "netexec":
        r = parse_netexec(output)
        return {"tool": "netexec", "hosts": r["hosts"], "creds": r["creds"], "network": [], "dns": []}

    if tool == "secretsdump":
        r = parse_secretsdump(output)
        return {"tool": "secretsdump", "hosts": [], "creds": r["creds"], "network": [], "dns": []}

    if tool == "hydra":
        r = parse_hydra(output)
        return {"tool": "hydra", "hosts": [], "creds": r["creds"], "network": [], "dns": []}

    fn = _EXTRA_TOOLS.get(tool)
    if fn:
        r = fn(output)
        r.setdefault("hosts", [])
        r.setdefault("creds", [])
        r.setdefault("network", [])
        r.setdefault("dns", [])
        return {"tool": tool, **r}

    return {"tool": tool, "hosts": [], "creds": [], "network": [], "dns": []}




# ── Impacket family & friends (termtrack, 2026-10-13) ────────────────
# Extraction contract: creds carry the identity metadata (user/domain/
# host/type) but NOT the secret material — auto-apply must never put a
# hash or password into project fields; the observation stays a draft.


def _parse_getuserspns(output: str) -> dict:
    """GetUserSPNs: enumerated SPN accounts + kerberoast hashes."""
    creds: list[dict] = []
    for line in output.splitlines():
        # format: $krb5tgs$23$*user$DOMAIN$spn*$<hash>
        m = re.search(r"\$krb5tgs\$\d+\$?\*([^$\s]+)\$([^$\s]+)", line)
        if m:
            user = m.group(1)
            domain = m.group(2)
            creds.append({"username": user, "domain": domain, "type": "hash",
                          "service": "kerberoast"})
            continue
        # SPN table rows: "MSSQLSvc/host.domain:1433   svc_account ..."
        m = re.match(r"^[A-Za-z][\w.-]*/[^\s]+\s+(\S+)", line.strip())
        if m:
            creds.append({"username": m.group(1), "domain": "", "type": "spn",
                          "service": "kerberoast"})
    return {"creds": creds}


def _parse_getnpusers(output: str) -> dict:
    """GetNPUsers: asreproast hashes + 'no password' accounts."""
    creds: list[dict] = []
    for line in output.splitlines():
        if "$krb5asrep" in line:
            m = re.search(r"\$krb5asrep\$\d+\*?([^$\s:]*)", line)
            creds.append({"username": (m.group(1) if m else "") or "unknown",
                          "domain": "", "type": "hash", "service": "asreproast"})
            continue
        m = re.search(r"User\s+(\S+)\s+doesn't have Kerberos preauthentication", line, re.I)
        if m:
            creds.append({"username": m.group(1), "domain": "", "type": "nopreauth",
                          "service": "asreproast"})
    return {"creds": creds}


def _parse_ntlmrelayx(output: str) -> dict:
    """ntlmrelayx: successful relays = access context."""
    creds: list[dict] = []
    for line in output.splitlines():
        m = re.search(
            r"Authentication succeeded.*?\\\\?([\w.-]+)\\([\w.$-]+)", line, re.I
        )
        if m:
            creds.append({"username": m.group(2), "domain": m.group(1),
                          "host": "", "type": "relay", "service": "smb"})
            continue
        m = re.search(r"Connecting to ([\d.]+) as ([\\\w.$-]+) SUCCEED", line)
        if m:
            creds.append({"username": m.group(2), "domain": "", "host": m.group(1),
                          "type": "relay", "service": "smb"})
            continue
        m = re.search(r"Authenticating against ([\d.]+) as ([\w.-]+)\\([\w.$-]+) SUCCEED", line)
        if m:
            creds.append({"username": m.group(3), "domain": m.group(2),
                          "host": m.group(1), "type": "relay", "service": "smb"})
    return {"creds": creds}


def _parse_psexec_family(output: str) -> dict:
    """psexec/smbexec/wmiexec/atexec: shell established = access context."""
    creds: list[dict] = []
    if re.search(r"Launching semi-interactive shell|\[\*\] Executing", output):
        creds.append({"username": "", "domain": "", "host": "",
                      "type": "shell", "service": "impacket"})
    if re.search(r"\[\*\] .+? SUCCEED", output):
        creds.append({"username": "", "domain": "", "host": "",
                      "type": "exec", "service": "impacket"})
    return {"creds": creds}


def _parse_responder(output: str) -> dict:
    """Responder: captured hashes → identity only."""
    creds: list[dict] = []
    for line in output.splitlines():
        m = re.search(r"(?:NTLMv2-SSP|NTLMv1-SSP) Hash\s*:([\w.$-]+)::([\w.-]+)", line)
        if m:
            creds.append({"username": m.group(1), "domain": m.group(2),
                          "host": "", "type": "hash", "service": "responder"})
    return {"creds": creds}


def _parse_smbclient(output: str) -> dict:
    """smbclient: server banner (OS/domain/server) — direct host context."""
    hosts: list[dict] = []
    m = re.search(r"Domain=\[([^\]]+)\]\s+OS=\[([^\]]*)\]\s+Server=\[([^\]]*)\]", output)
    if m:
        hosts.append({"domain": m.group(1), "os": m.group(2) or "",
                      "hostname": m.group(3) or "", "ip": ""})
    return {"hosts": hosts}


def _parse_whatweb(output: str) -> dict:
    """whatweb: tech fingerprints per target."""
    hosts: list[dict] = []
    for line in output.splitlines():
        m = re.match(r"^(?:https?://)?([^\s\[]+)\s+\[(\d{3})\]\s*(.*)$", line.strip())
        if m:
            target, status, rest = m.groups()
            ip = target if _is_ip(target) else ""
            hosts.append({"ip": ip, "hostname": "" if ip else target,
                          "services": [t.strip() for t in rest.split(",")[:8] if t.strip()]})
    return {"hosts": [h for h in hosts if h["ip"] or h["hostname"]]}


# impacket connection strings in the COMMAND itself:
# `impacket-psexec CORP\\user:pass@10.0.0.5` / `-hashes :LM:NT DOM\\user@host`
_CONN_RE = re.compile(
    r"(?P<domain>[A-Za-z0-9.-]+)?\\?(?P<user>[A-Za-z0-9.$_-]+)"
    r"(?::(?P<secret>[^@\s]+))?@(?P<target>(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+)"
)


def parse_impacket_connection(command: str) -> dict:
    """Identity + target from an impacket-style connection string.

    The secret is detected and reported as `has_secret` — never returned
    in the payload. Target lands in hosts so the access draft attaches
    to the right machine."""
    m = _CONN_RE.search(command)
    if not m:
        return {"creds": [], "hosts": []}
    domain = (m.group("domain") or "").rstrip("\\")
    user = m.group("user")
    target = m.group("target")
    if user.lower() in ("impacket",) or not user:
        return {"creds": [], "hosts": []}
    host = {"ip": target} if _is_ip(target) else {"hostname": target}
    return {
        "creds": [{
            "username": user, "domain": domain,
            "host": target if _is_ip(target) else "",
            "type": "conn", "service": "impacket",
            "has_secret": bool(m.group("secret")),
        }],
        "hosts": [host],
    }


# ── Extra tools: network/DNS context (termtrack, 2026-10-13) ─────────
# These commands' whole output IS the signal; registered explicitly.

import ipaddress  # noqa: E402

_IP_TOKEN = r"(?:\d{1,3}\.){3}\d{1,3}"
_CIDR_RE = re.compile(rf"\b({_IP_TOKEN}/\d{{1,2}})\b")


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _parse_ip_addr(output: str) -> dict:
    """`ip addr`: interfaces and their networks."""
    network: list[dict] = []
    iface = ""
    for line in output.splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)[:@]", line)
        if m:
            iface = m.group(1)
            continue
        m = re.search(rf"\binet\s+({_IP_TOKEN}/\d{{1,2}})", line)
        if m and iface:
            try:
                net = ipaddress.ip_network(m.group(1), strict=False)
            except ValueError:
                continue
            network.append({"kind": "iface", "iface": iface, "cidr": str(net), "prefix": net.prefixlen})
            continue
        m = re.search(r"\binet6\s+([0-9a-f:]+/\d{1,3})", line)
        if m and iface:
            network.append({"kind": "iface6", "iface": iface, "cidr": m.group(1)})
    return {"network": network}


def _parse_ip_route(output: str) -> dict:
    """`ip route`: reachable subnets (scope-extension candidates)."""
    network: list[dict] = []
    for line in output.splitlines():
        s = line.strip()
        if not s or s.split()[0] in ("default", "blackhole", "throw", "unreachable", "prohibit"):
            continue
        m = _CIDR_RE.search(s)
        if not m:
            continue
        via = re.search(rf"\bvia\s+({_IP_TOKEN})", s)
        dev = re.search(r"\bdev\s+(\S+)", s)
        network.append({
            "kind": "route",
            "cidr": m.group(1),
            "via": via.group(1) if via else "",
            "dev": dev.group(1) if dev else "",
        })
    return {"network": network}


def _parse_ss(output: str) -> dict:
    """`ss -tulpen`: listeners on the box the operator is on."""
    ports: list[str] = []
    services: list[str] = []
    for line in output.splitlines():
        m = re.match(r"^(tcp|udp)\S*\s+\S+\s+\S+\s+\S*\[?(?:[0-9a-f:]+:)?(\d+)\]?", line)
        if not m:
            continue
        proto, port = m.group(1), m.group(2)
        pm = re.search(r'users:\(\(\("([^"]+)"', line)
        ports.append(f"{port}/{proto}")
        services.append(pm.group(1) if pm else f"{proto}/{port}")
    hosts = [{"ip": "127.0.0.1", "ports": ports, "services": services, "_local": True}] if ports else []
    return {"hosts": hosts}


def _parse_dns_lookup(output: str) -> dict:
    """dig / nslookup / host: resolution answers."""
    dns: list[dict] = []
    hosts: list[dict] = []
    in_answer = False
    qname = ""
    qm = re.search(r";?<?([A-Za-z0-9.-]+\.?)>?(?:\s+\d+)?\s+IN\s+(?:A|AAAA|CNAME|PTR)", output)
    if qm:
        qname = qm.group(1).rstrip(".")
    for line in output.splitlines():
        s = line.strip()
        if re.match(r"^;;\s*(ANSWER|HEADER|OPT|SECTION)", s) or "ANSWER SECTION" in s:
            in_answer = "ANSWER" in s.upper()
            continue
        if re.match(r"^;;|^(AUTHORITY|ADDITIONAL)", s):
            in_answer = False
            continue
        if not in_answer:
            m = re.match(rf"^(\S+)\s+has\s+(?:address|IPv6 address)\s+({_IP_TOKEN})", s)
            if m:
                dns.append({"name": m.group(1).rstrip("."), "type": "A", "value": m.group(2)})
                hosts.append({"ip": m.group(2), "hostname": m.group(1).rstrip(".")})
                continue
            m = re.match(rf"^Address:\s+({_IP_TOKEN})$", s)
            if m and qname:
                dns.append({"name": qname, "type": "A", "value": m.group(1)})
                hosts.append({"ip": m.group(1), "hostname": qname})
            continue
        m = re.match(r"(\S+\.?)\s+\d+\s+IN\s+(A|AAAA|CNAME|PTR)\s+(\S+)", s)
        if m:
            name, rtype, val = m.group(1).rstrip("."), m.group(2), m.group(3).rstrip(".")
            dns.append({"name": name, "type": rtype, "value": val})
            if rtype in ("A", "AAAA") and _is_ip(val):
                hosts.append({"ip": val, "hostname": name if not qname or name == qname else ""})
    return {"dns": dns, "hosts": [h for h in hosts if h.get("hostname") or h.get("ip")]}


for _name, _pat in [
    ("ip_addr", re.compile(r"\bip\s+(?:-[a-zA-Z]+\s+)*a(?:ddr?)?\b", re.I)),
    ("ip_route", re.compile(r"\bip\s+(?:-[a-zA-Z]+\s+)*r(?:oute)?\b", re.I)),
    ("ss", re.compile(r"(?:^|\s|;|&&)ss\s+(?:-[a-zA-Z]+\s+)*-?[a-zA-Z]", re.I)),
    ("dig", re.compile(r"(?:^|\s|;|&&)dig\b", re.I)),
    ("nslookup", re.compile(r"(?:^|\s|;|&&)nslookup\b", re.I)),
    ("host", re.compile(r"(?:^|\s|;|&&)host\s+\S+", re.I)),
]:
    _TOOL_PATTERNS.append((_name, _pat))

_EXTRA_TOOLS = {
    "ip_addr": _parse_ip_addr,
    "ip_route": _parse_ip_route,
    "ss": _parse_ss,
    "dig": _parse_dns_lookup,
    "nslookup": _parse_dns_lookup,
    "host": _parse_dns_lookup,
    "getuserspns": _parse_getuserspns,
    "getnpusers": _parse_getnpusers,
    "ntlmrelayx": _parse_ntlmrelayx,
    "psexec_family": _parse_psexec_family,
    "responder": _parse_responder,
    "smbclient": _parse_smbclient,
    "whatweb": _parse_whatweb,
}
