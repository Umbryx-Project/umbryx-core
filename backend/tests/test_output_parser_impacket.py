"""output_parser: impacket-family + network-context parsers.

These parsers (termtrack 2026-10-13) shipped without tests; the gap
became visible when the Shannon reformat pass moved their lines into
the SonarQube new-code window. Samples below mimic real tool output
(getuserspns/getnpusers/ntlmrelayx/psexec family/responder/smbclient/
whatweb/ip addr/ip route/ss)."""

from app.core.output_parser import (
    _parse_getnpusers,
    _parse_getuserspns,
    _parse_ip_addr,
    _parse_ip_route,
    _parse_ntlmrelayx,
    _parse_psexec_family,
    _parse_responder,
    _parse_smbclient,
    _parse_ss,
    _parse_whatweb,
    parse_impacket_connection,
    parse_output,
)


class TestGetUserSPNs:
    def test_kerberoast_hash_and_spn_row(self):
        out = (
            "ServicePrincipalName: MSSQLSvc/db01.corp.local:1433\n"
            "     $krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc~db01.corp.local:1433*$a1b2c3d4\n"
            "MSSQLSvc/db01.corp.local:1433    sqlsvc\n"
        )
        creds = _parse_getuserspns(out)["creds"]
        by_type = {c["type"]: c for c in creds}
        assert by_type["hash"]["username"] == "sqlsvc"
        assert by_type["hash"]["domain"] == "CORP.LOCAL"
        assert by_type["spn"]["username"] == "sqlsvc"

    def test_no_spns_no_creds(self):
        assert _parse_getuserspns("nothing here\n")["creds"] == []


class TestGetNPUsers:
    def test_asrep_hash_and_nopreauth(self):
        out = (
            "$krb5asrep$23*bob@CORP:4f5a6b7c8d9e0f1a2b3c\n"
            "User backup doesn't have Kerberos preauthentication\n"
        )
        creds = _parse_getnpusers(out)["creds"]
        by_type = {c["type"]: c for c in creds}
        assert by_type["hash"]["username"] == "bob@CORP"
        assert by_type["hash"]["service"] == "asreproast"
        assert by_type["nopreauth"]["username"] == "backup"

    def test_empty(self):
        assert _parse_getnpusers("")["creds"] == []


class TestNtlmrelayx:
    RELAY_OUT = (
        "[*] Authenticating against 10.0.1.6 as CORP\\dave SUCCEED\n"
        "[+] Authentication succeeded relaying SMB\\CORP\\jim\n"
        "[*] Connecting to 10.0.1.5 as CORP\\alice SUCCEED\n"
    )

    def test_all_three_success_shapes(self):
        creds = _parse_ntlmrelayx(self.RELAY_OUT)["creds"]
        assert len(creds) == 3
        jim = next(c for c in creds if c["username"] == "jim")
        assert jim["domain"] == "CORP" and jim["type"] == "relay"
        alice = next(c for c in creds if "alice" in c["username"])
        assert alice["host"] == "10.0.1.5"
        dave = next(c for c in creds if c["username"] == "dave")
        assert dave["host"] == "10.0.1.6" and dave["domain"] == "CORP"

    def test_failed_relay_yields_nothing(self):
        out = "[-] Authenticating against 10.0.1.6 as CORP\\dave FAILED\n"
        assert _parse_ntlmrelayx(out)["creds"] == []


class TestPsexecFamily:
    def test_shell_and_exec_contexts(self):
        out = "[*] Executing service\nLaunching semi-interactive shell\n[*] Service SUCCEED\n"
        creds = _parse_psexec_family(out)["creds"]
        types = sorted(c["type"] for c in creds)
        assert types == ["exec", "shell"]
        assert all(c["service"] == "impacket" for c in creds)

    def test_quiet_output_no_creds(self):
        assert _parse_psexec_family("[*] Opening share...\n")["creds"] == []


class TestResponder:
    def test_ntlmv1_and_v2_hashes(self):
        out = (
            "[+] NTLMv2-SSP Hash :ted::CORP:1122334455667788\n"
            "[+] NTLMv1-SSP Hash :admin::HEX:0123\n"
        )
        creds = _parse_responder(out)["creds"]
        assert len(creds) == 2
        assert creds[0]["username"] == "ted" and creds[0]["domain"] == "CORP"
        assert creds[1]["username"] == "admin"

    def test_no_hashes(self):
        assert _parse_responder("[!] LLMNR poisoned\n")["creds"] == []


class TestSmbclient:
    def test_domain_os_server_row(self):
        out = "Domain=[CORP] OS=[Windows Server 2016] Server=[WEB01]\n"
        hosts = _parse_smbclient(out)["hosts"]
        assert hosts == [
            {"domain": "CORP", "os": "Windows Server 2016", "hostname": "WEB01", "ip": ""}
        ]

    def test_no_banner(self):
        assert _parse_smbclient("tree connect failed\n")["hosts"] == []


class TestWhatweb:
    def test_ip_and_hostname_targets(self):
        out = (
            "10.0.0.99 [200] Apache[2.4.41], PHP[7.4]\n"
            "web01.corp.local [302] Redirect[http://intranet]\n"
        )
        hosts = _parse_whatweb(out)["hosts"]
        by_ip = {h.get("ip"): h for h in hosts}
        assert by_ip["10.0.0.99"]["services"][0] == "Apache[2.4.41]"
        hostname_row = next(h for h in hosts if h["hostname"])
        assert hostname_row["hostname"] == "web01.corp.local"

    def test_unparseable_line_dropped(self):
        assert _parse_whatweb("garbage without status\n")["hosts"] == []


class TestImpacketConnection:
    def test_psexec_with_secret(self):
        r = parse_impacket_connection(r"impacket-psexec corp.local\joe:s3cret@10.0.0.5")
        cred = r["creds"][0]
        assert cred["username"] == "joe"
        assert cred["domain"] == "corp.local"
        assert cred["host"] == "10.0.0.5"
        assert cred["has_secret"] is True
        assert cred["type"] == "conn"
        assert r["hosts"] == [{"ip": "10.0.0.5"}]

    def test_hostname_target_has_secret_host_empty(self):
        r = parse_impacket_connection(r"impacket-smbexec corp\alice@win2019.corp")
        cred = r["creds"][0]
        assert cred["has_secret"] is False
        assert cred["host"] == ""
        assert r["hosts"] == [{"hostname": "win2019.corp"}]

    def test_hashes_form_identity_without_secret(self):
        r = parse_impacket_connection(r"impacket-atexec -hashes :LM:NT corp\svc@10.0.0.9")
        assert r["creds"][0]["username"] == "svc"
        assert r["creds"][0]["domain"] == "corp"
        # the -hashes material is not part of the connection string secret;
        # nothing secret lands in the payload either way
        assert "LM" not in str(r) and "NT" not in str(r)

    def test_default_user_rejected(self):
        assert parse_impacket_connection("connect impacket@10.0.0.7") == {"creds": [], "hosts": []}

    def test_no_connection_string(self):
        assert parse_impacket_connection("ls -la /tmp") == {"creds": [], "hosts": []}


class TestIpAddr:
    OUT = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic eth0\n"
        "    inet6 fe80::5054:ff:fe9e:1a2b/64 scope link\n"
    )

    def test_ifaces_and_prefixes(self):
        net = _parse_ip_addr(self.OUT)["network"]
        v4 = {(n["iface"], n["kind"]): n for n in net if n["kind"] == "iface"}
        assert v4[("lo", "iface")]["cidr"] == "127.0.0.0/8"
        assert v4[("lo", "iface")]["prefix"] == 8
        assert v4[("eth0", "iface")]["cidr"] == "192.168.1.0/24"
        v6 = [n for n in net if n["kind"] == "iface6"]
        assert v6 and v6[0]["iface"] == "eth0"
        assert v6[0]["cidr"] == "fe80::5054:ff:fe9e:1a2b/64"

    def test_empty_output(self):
        assert _parse_ip_addr("")["network"] == []


class TestIpRoute:
    OUT = (
        "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        "10.0.0.0/8 via 10.0.0.254 dev tun0 proto static\n"
        "172.16.0.0/16 dev docker0\n"
    )

    def test_routes_with_and_without_gateway(self):
        net = _parse_ip_route(self.OUT)["network"]
        assert len(net) == 2  # default route is skipped
        tun = next(n for n in net if n["dev"] == "tun0")
        assert tun == {"kind": "route", "cidr": "10.0.0.0/8", "via": "10.0.0.254", "dev": "tun0"}
        docker = next(n for n in net if n["dev"] == "docker0")
        assert docker["via"] == ""

    def test_dispatch_via_parse_output(self):
        r = parse_output("ip route", self.OUT)
        assert r["tool"] == "ip_route"
        assert len(r["network"]) == 2


class TestSs:
    # modern iproute layout: Netid State Recv-Q Send-Q Local:Port …
    OUT = (
        'tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*   users:(("sshd",pid=812,fd=3))\n'
        "udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*\n"
        'tcp   LISTEN 0      5            [::]:8080                     users:(("app",pid=900,fd=9))\n'
    )

    def test_local_listeners(self):
        hosts = _parse_ss(self.OUT)["hosts"]
        assert len(hosts) == 1
        h = hosts[0]
        assert h["_local"] is True and h["ip"] == "127.0.0.1"
        # ports come from the Local:Port column — never the Send-Q digits
        assert h["ports"] == ["22/tcp", "68/udp", "8080/tcp"]
        # named process for sshd, generated label for the anonymous ones
        assert h["services"][0] == "sshd"
        assert h["services"][1] == "udp/68"
        assert h["services"][2] == "app"

    def test_netstat_style_layout_still_parsed(self):
        out = 'tcp   0      0          0.0.0.0:4444        0.0.0.0:*   users:(("handler",pid=1,fd=4))\n'
        h = _parse_ss(out)["hosts"][0]
        assert h["ports"] == ["4444/tcp"]
        assert h["services"] == ["handler"]

    def test_no_listeners_no_host(self):
        assert _parse_ss("Netid State Recv-Q\n")["hosts"] == []

    def test_dispatch_via_parse_output(self):
        r = parse_output("ss -tulpen", self.OUT)
        assert r["tool"] == "ss"
        assert r["hosts"][0]["ports"] == ["22/tcp", "68/udp", "8080/tcp"]
