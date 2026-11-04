"""
Unit tests for the firewall config parser abstraction (core/firewall_parsers/).
Pure — no DB, no app.
"""

import json
import time

from app.core.firewall_parsers import FirewallParserRegistry
from app.core.firewall_parsers.cisco_asa import CiscoASAParser
from app.core.firewall_parsers.cisco_ios import CiscoIOSParser, _decode_type7
from app.core.firewall_parsers.fortinet import FortinetParser
from app.core.firewall_parsers.huawei_vrp import HuaweiVRPParser
from app.core.firewall_parsers.mikrotik import MikroTikParser
from app.core.firewall_parsers.paloalto import PaloAltoParser
from app.core.firewall_parsers.pfsense import PfSenseParser
from app.core.firewall_parsers.unifi import UniFiParser
from app.core.firewall_parsers.util import (
    extract_ip_and_mac,
    is_public_ip,
    looks_like_mac,
    normalize_mac,
)

CISCO_CFG = """
!
hostname EdgeRouter1
!
version 15.2
!
object-group network SALES_NET
 network-object 10.10.10.0 255.255.255.0
!
interface GigabitEthernet0/0
 description WAN uplink
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet0/1
 description LAN
 ip address 10.10.10.1 255.255.255.0
 switchport access vlan 10
!
ip route 0.0.0.0 0.0.0.0 203.0.113.2
!
ip access-list extended OUTSIDE_IN
 permit tcp any any eq 443
 permit ip any any
!
access-list 101 permit ip object-group SALES_NET any
!
ip nat inside source static 10.10.10.5 203.0.113.5
ip nat inside source list 1 interface GigabitEthernet0/0 overload
!
vlan 10
 name SALES
!
username admin privilege 15 password 7 0822455D0A16
username bob secret 5 $1$abcd$hashvalue
!
"""

MIKROTIK_CFG = """
# jan/02/2026 12:00:00 by RouterOS 7.11
# model = RB750Gr3
/interface bridge
add name=bridge1
/interface vlan
add interface=bridge1 name=vlan10 vlan-id=10
/ip address
add address=192.168.88.1/24 interface=bridge1
add address=10.10.10.1/24 interface=vlan10
/ip route
add distance=1 gateway=192.168.88.254
/ip firewall filter
add action=accept chain=input protocol=icmp
add action=drop chain=input connection-state=invalid
add action=accept chain=forward src-address=192.168.88.0/24 dst-address=0.0.0.0/0 protocol=tcp dst-port=443
add action=accept chain=input src-address=0.0.0.0/0 dst-address=0.0.0.0/0
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1
add action=dst-nat chain=dstnat dst-address=203.0.113.5 dst-port=8080 to-addresses=192.168.88.10 to-ports=80
/system identity
set name=MyRouter
/user
add group=full name=admin
"""


ASA_CFG = """
: Saved
:
ASA Version 9.12(4)
!
hostname asa-fw1
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 5.5.5.1 255.255.255.252
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.10.10.1 255.255.255.0
!
object network SALES_HOST
 host 10.10.10.5
object-group network SALES_NET
 network-object 10.10.10.0 255.255.255.0
!
access-list OUTSIDE_IN extended permit tcp any any eq 443
access-list OUTSIDE_IN extended permit ip any any
access-list SALES_ACL extended permit ip object-group SALES_NET any
!
nat (inside,outside) source static SALES_HOST SALES_HOST
!
username admin password 8Ry2YjIyt7RRXU24 encrypted privilege 15
"""

HUAWEI_CFG = """
sysname CoreSW1
#
interface GigabitEthernet0/0/1
 ip address 5.5.5.1 255.255.255.252
#
interface GigabitEthernet0/0/2
 ip address 10.10.10.1 255.255.255.0
#
ip route-static 0.0.0.0 0.0.0.0 5.5.5.2
#
acl number 3000
 rule 5 permit ip source 10.10.10.0 0.0.0.255 destination any
 rule 10 permit tcp source any destination any destination-port eq 443
#
vlan batch 10 20
#
local-user admin password irreversible-cipher hashvalue
local-user bob password simple plaintextpw
#
"""

FORTI_CFG = """
#config-version=FGT60E-7.0.1
config system global
    set hostname "FW-Edge1"
end
config system interface
    edit "port1"
        set ip 5.5.5.1 255.255.255.252
    next
    edit "port2"
        set ip 10.10.10.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
config firewall vip
    edit "vip1"
        set extip 5.5.5.5
        set mappedip "10.10.10.5"
        set extport 8080
        set mappedport 80
    next
end
config system admin
    edit "admin"
        set password ENC SH2mXnBlobHere
    next
end
"""

PALOALTO_CFG = """
set deviceconfig system hostname PA-Edge1
set network interface ethernet ethernet1/1 layer3 ip 5.5.5.1/30
set network interface ethernet ethernet1/2 layer3 ip 10.10.10.1/24
set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default nexthop ip-address 5.5.5.2
set address-object SALES-NET ip-netmask 10.10.10.0/24
set rulebase security rules ALLOW-WEB from any to any source any destination any application any service any action allow
set rulebase nat rules NAT1 source-translation dynamic-ip-and-port translated-address 5.5.5.10
set mgt-config users admin phash somehashvalue
"""

UNIFI_CFG = json.dumps(
    {
        "system": {"host-name": "USG-Edge1"},
        "interfaces": {
            "ethernet": {
                "eth0": {"address": ["5.5.5.1/30"], "description": "WAN"},
                "eth1": {"address": ["10.10.10.1/24"], "description": "LAN"},
            }
        },
        "protocols": {"static": {"route": {"0.0.0.0/0": {"next-hop": {"5.5.5.2": {}}}}}},
        "firewall": {
            "name": {
                "WAN_IN": {
                    "rule": {
                        "10": {
                            "action": "accept",
                            "source": {"address": "0.0.0.0/0"},
                            "destination": {"port": "443"},
                            "protocol": "tcp",
                        }
                    }
                }
            }
        },
        "service": {
            "nat": {
                "rule": {
                    "5000": {
                        "type": "destination",
                        "inside-address": {"address": "10.10.10.5"},
                        "outside-address": {"address": "5.5.5.5"},
                        "protocol": "tcp",
                    }
                }
            }
        },
    }
)

PFSENSE_CFG = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>pfsense-edge</hostname>
    <user><name>admin</name><bcrypt-hash>somehash</bcrypt-hash></user>
  </system>
  <interfaces>
    <wan><if>em0</if><ipaddr>5.5.5.1</ipaddr><subnet>30</subnet></wan>
    <lan><if>em1</if><ipaddr>10.10.10.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <staticroutes>
    <route><network>0.0.0.0/0</network><gateway>WAN_GW</gateway></route>
  </staticroutes>
  <filter>
    <rule><type>pass</type><source><any/></source><destination><any/><port>443</port></destination><protocol>tcp</protocol></rule>
  </filter>
  <nat>
    <rule><source><address>10.10.10.5</address></source><destination><address>5.5.5.5</address></destination></rule>
  </nat>
  <vlans>
    <vlan><if>em1</if><tag>10</tag><descr>SALES</descr></vlan>
  </vlans>
</pfsense>
"""

PFSENSE_XXE_ATTEMPT = """<?xml version="1.0"?>
<!DOCTYPE pfsense [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<pfsense><system><hostname>&xxe;</hostname></system></pfsense>
"""

_ALL_SAMPLES = {
    "cisco_ios": CISCO_CFG,
    "cisco_asa": ASA_CFG,
    "mikrotik": MIKROTIK_CFG,
    "huawei_vrp": HUAWEI_CFG,
    "fortinet": FORTI_CFG,
    "paloalto": PALOALTO_CFG,
    "unifi": UNIFI_CFG,
    "pfsense": PFSENSE_CFG,
}


class TestRegistry:
    def test_detect_vendor_cisco(self):
        assert FirewallParserRegistry.detect_vendor(CISCO_CFG) == "cisco_ios"

    def test_detect_vendor_mikrotik(self):
        assert FirewallParserRegistry.detect_vendor(MIKROTIK_CFG) == "mikrotik"

    def test_detect_vendor_unrecognized(self):
        assert FirewallParserRegistry.detect_vendor("this is not a router config at all") is None

    def test_cisco_does_not_misdetect_as_mikrotik(self):
        assert MikroTikParser().detect(CISCO_CFG) is False

    def test_mikrotik_does_not_misdetect_as_cisco(self):
        assert CiscoIOSParser().detect(MIKROTIK_CFG) is False

    def test_list_vendors_includes_all_eight(self):
        vendors = FirewallParserRegistry.list_vendors()
        for key in _ALL_SAMPLES:
            assert key in vendors

    def test_get_unknown_vendor_returns_none(self):
        assert FirewallParserRegistry.get("nonexistent_vendor") is None

    def test_each_sample_detects_as_its_own_vendor(self):
        for vendor_key, sample in _ALL_SAMPLES.items():
            assert FirewallParserRegistry.detect_vendor(sample) == vendor_key, vendor_key

    def test_each_sample_matches_exactly_one_parser(self):
        # Cross-vendor negative case: every sample must be recognized by
        # exactly its own parser, never by any other registered parser —
        # otherwise detect_vendor()'s "first match wins" could silently
        # misroute a real upload depending on registration order.
        vendors = FirewallParserRegistry.list_vendors()
        for vendor_key, sample in _ALL_SAMPLES.items():
            matches = [v for v in vendors if FirewallParserRegistry.get(v).detect(sample)]
            assert matches == [vendor_key], f"{vendor_key} sample matched {matches}"


class TestCiscoIOSParser:
    def setup_method(self):
        self.parsed = CiscoIOSParser().parse(CISCO_CFG)

    def test_system_info(self):
        assert self.parsed.system.hostname == "EdgeRouter1"
        assert self.parsed.system.os_version == "15.2"

    def test_interfaces(self):
        names = {i.name for i in self.parsed.interfaces}
        assert names == {"GigabitEthernet0/0", "GigabitEthernet0/1"}
        wan = next(i for i in self.parsed.interfaces if i.name == "GigabitEthernet0/0")
        assert wan.ip_address == "203.0.113.1"
        assert wan.netmask == "255.255.255.252"
        lan = next(i for i in self.parsed.interfaces if i.name == "GigabitEthernet0/1")
        assert lan.vlan == "10"

    def test_routes(self):
        assert len(self.parsed.routes) == 1
        assert self.parsed.routes[0].next_hop == "203.0.113.2"

    def test_object_group_expanded_in_acl(self):
        # access-list 101 references object-group SALES_NET — must be
        # expanded to concrete addresses, never left as an opaque name.
        rule = next(r for r in self.parsed.acl_rules if "101" in r.raw)
        assert "10.10.10.0" in rule.source
        assert "group:" not in rule.source

    def test_acl_rules(self):
        assert len(self.parsed.acl_rules) == 3
        tcp443 = next(r for r in self.parsed.acl_rules if r.destination_port == "eq 443")
        assert tcp443.action == "permit"
        assert tcp443.protocol == "tcp"

    def test_nat_rules(self):
        assert len(self.parsed.nat_rules) == 2
        static = next(r for r in self.parsed.nat_rules if r.kind == "static")
        assert static.inside_address == "10.10.10.5"
        assert static.outside_address == "203.0.113.5"

    def test_vlans(self):
        assert len(self.parsed.vlans) == 1
        assert self.parsed.vlans[0].name == "SALES"

    def test_object_groups(self):
        assert len(self.parsed.object_groups) == 1
        assert self.parsed.object_groups[0].name == "SALES_NET"

    def test_local_users_type7_decoded(self):
        admin = next(u for u in self.parsed.local_users if u.username == "admin")
        # 0822455D0A16 is the canonical Cisco type-7 test vector for "cisco"
        assert admin.recoverable_secret == "cisco"
        bob = next(u for u in self.parsed.local_users if u.username == "bob")
        assert bob.recoverable_secret is None  # type-5 MD5 hash, not reversible

    def test_get_vendor_info(self):
        info = CiscoIOSParser().get_vendor_info()
        assert info.vendor_key == "cisco_ios"


class TestType7Decode:
    def test_known_vector(self):
        assert _decode_type7("0822455D0A16") == "cisco"

    def test_malformed_input_returns_none_not_raise(self):
        assert _decode_type7("") is None
        assert _decode_type7("zz") is None
        assert _decode_type7("99xyz") is None
        assert _decode_type7("9") is None


class TestMikroTikParser:
    def setup_method(self):
        self.parsed = MikroTikParser().parse(MIKROTIK_CFG)

    def test_system_info(self):
        assert self.parsed.system.hostname == "MyRouter"
        assert "7.11" in self.parsed.system.os_version

    def test_interfaces(self):
        bridge = next(i for i in self.parsed.interfaces if i.name == "bridge1")
        assert bridge.ip_address == "192.168.88.1"
        assert bridge.netmask == "24"
        vlan_if = next(i for i in self.parsed.interfaces if i.name == "vlan10")
        assert vlan_if.vlan == "10"

    def test_routes(self):
        assert self.parsed.routes[0].next_hop == "192.168.88.254"

    def test_acl_rules_action_mapping(self):
        actions = {r.raw: r.action for r in self.parsed.acl_rules}
        assert any(a == "permit" for a in actions.values())
        assert any(a == "deny" for a in actions.values())

    def test_nat_rules(self):
        static = next(r for r in self.parsed.nat_rules if r.kind == "static")
        assert static.inside_address == "192.168.88.10"
        assert static.outside_address == "203.0.113.5"
        dynamic = next(r for r in self.parsed.nat_rules if r.kind == "dynamic")
        assert dynamic.raw.startswith("add action=masquerade")

    def test_vlans(self):
        assert self.parsed.vlans[0].vlan_id == "10"

    def test_local_users_have_no_recoverable_secret(self):
        assert all(u.recoverable_secret is None for u in self.parsed.local_users)


class TestParserResilience:
    """Malformed/adversarial input must not crash or hang either parser."""

    def _assert_fast_and_no_crash(self, parser, text):
        start = time.monotonic()
        parsed = parser.parse(text)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0
        assert parsed is not None

    def test_cisco_handles_garbage(self):
        self._assert_fast_and_no_crash(CiscoIOSParser(), "interface \n ip address\n" * 500)

    def test_cisco_handles_empty(self):
        self._assert_fast_and_no_crash(CiscoIOSParser(), "")

    def test_cisco_handles_huge_single_line(self):
        self._assert_fast_and_no_crash(
            CiscoIOSParser(), "access-list 1 permit ip any any " + "a" * 200_000
        )

    def test_mikrotik_handles_garbage(self):
        self._assert_fast_and_no_crash(
            MikroTikParser(), "/ip firewall filter\nadd " + "x=y " * 5000
        )

    def test_mikrotik_handles_unterminated_quote(self):
        self._assert_fast_and_no_crash(
            MikroTikParser(), '/ip firewall filter\nadd comment="unterminated'
        )

    def test_mikrotik_handles_backslash_continuation_storm(self):
        self._assert_fast_and_no_crash(MikroTikParser(), "\\\n" * 2000 + "add name=x")

    def test_asa_handles_garbage(self):
        self._assert_fast_and_no_crash(CiscoASAParser(), "interface \n nameif\n" * 500)

    def test_huawei_handles_garbage(self):
        self._assert_fast_and_no_crash(HuaweiVRPParser(), "acl number\n rule permit\n" * 500)

    def test_fortinet_handles_garbage(self):
        self._assert_fast_and_no_crash(FortinetParser(), 'config x\nedit "y"\nset ' + "a b " * 5000)

    def test_fortinet_handles_unterminated_quote(self):
        self._assert_fast_and_no_crash(
            FortinetParser(), 'config x\nedit "y"\nset comment "unterminated'
        )

    def test_paloalto_handles_garbage(self):
        self._assert_fast_and_no_crash(
            PaloAltoParser(), "set network interface ethernet " + "x " * 5000
        )

    def test_unifi_handles_non_json(self):
        self._assert_fast_and_no_crash(UniFiParser(), "this is not json {{{")

    def test_unifi_handles_huge_input(self):
        self._assert_fast_and_no_crash(UniFiParser(), "not json " * 50000)

    def test_pfsense_handles_non_xml(self):
        self._assert_fast_and_no_crash(PfSenseParser(), "this is not xml <<<")

    def test_pfsense_handles_malformed_xml(self):
        self._assert_fast_and_no_crash(PfSenseParser(), "<pfsense><interfaces><wan>")


class TestPublicIpClassification:
    def test_public_addresses(self):
        assert is_public_ip("5.5.5.5") is True
        assert is_public_ip("1.1.1.1") is True

    def test_private_and_reserved_addresses(self):
        assert is_public_ip("10.0.0.1") is False
        assert is_public_ip("192.168.1.1") is False
        assert is_public_ip("172.16.0.1") is False
        assert is_public_ip("127.0.0.1") is False
        assert is_public_ip("169.254.1.1") is False
        assert is_public_ip("203.0.113.1") is False  # RFC5737 documentation range
        assert is_public_ip("100.64.0.1") is False  # CGNAT

    def test_malformed_input_returns_false_not_raise(self):
        assert is_public_ip("") is False
        assert is_public_ip("not-an-ip") is False
        assert is_public_ip("999.999.999.999") is False

    def test_wan_interface_flagged_public_across_vendors(self):
        # CISCO_CFG/MIKROTIK_CFG use RFC5737 documentation-range WAN
        # addresses (203.0.113.x) — correctly non-global — so they're
        # covered separately by is_public_ip()'s own tests above, not here.
        vendors_with_real_public_wan = set(_ALL_SAMPLES) - {"cisco_ios", "mikrotik"}
        for vendor_key in vendors_with_real_public_wan:
            parsed = FirewallParserRegistry.get(vendor_key).parse(_ALL_SAMPLES[vendor_key])
            public_ifaces = [i for i in parsed.interfaces if i.is_public]
            private_ifaces = [i for i in parsed.interfaces if i.ip_address and not i.is_public]
            assert len(public_ifaces) == 1, vendor_key
            assert public_ifaces[0].ip_address == "5.5.5.1", vendor_key
            assert len(private_ifaces) == 1, vendor_key


class TestCiscoASAParser:
    def setup_method(self):
        self.parsed = CiscoASAParser().parse(ASA_CFG)

    def test_system_info(self):
        assert self.parsed.system.hostname == "asa-fw1"
        assert self.parsed.system.os_version == "9.12(4)"

    def test_interfaces_and_zones(self):
        outside = next(i for i in self.parsed.interfaces if i.zone == "outside")
        assert outside.ip_address == "5.5.5.1"
        assert outside.is_public is True
        inside = next(i for i in self.parsed.interfaces if i.zone == "inside")
        assert inside.ip_address == "10.10.10.1"
        assert inside.is_public is False

    def test_object_group_expanded_in_acl(self):
        rule = next(r for r in self.parsed.acl_rules if "SALES_ACL" in r.raw)
        assert "10.10.10.0" in rule.source
        assert "object:" not in rule.source

    def test_acl_rules(self):
        assert len(self.parsed.acl_rules) == 3
        tcp443 = next(r for r in self.parsed.acl_rules if r.destination_port == "eq 443")
        assert tcp443.action == "permit"

    def test_nat_rule(self):
        assert len(self.parsed.nat_rules) == 1
        assert self.parsed.nat_rules[0].kind == "static"

    def test_local_users_never_recoverable(self):
        assert all(u.recoverable_secret is None for u in self.parsed.local_users)

    def test_get_vendor_info(self):
        assert CiscoASAParser().get_vendor_info().vendor_key == "cisco_asa"


class TestHuaweiVRPParser:
    def setup_method(self):
        self.parsed = HuaweiVRPParser().parse(HUAWEI_CFG)

    def test_system_info(self):
        assert self.parsed.system.hostname == "CoreSW1"

    def test_interfaces(self):
        assert len(self.parsed.interfaces) == 2

    def test_routes(self):
        assert self.parsed.routes[0].next_hop == "5.5.5.2"

    def test_acl_rules(self):
        assert len(self.parsed.acl_rules) == 2
        tcp443 = next(r for r in self.parsed.acl_rules if r.destination_port == "eq 443")
        assert tcp443.action == "permit"

    def test_vlans(self):
        assert {v.vlan_id for v in self.parsed.vlans} == {"10", "20"}

    def test_local_user_simple_password_recoverable(self):
        bob = next(u for u in self.parsed.local_users if u.username == "bob")
        assert bob.recoverable_secret == "plaintextpw"
        admin = next(u for u in self.parsed.local_users if u.username == "admin")
        assert admin.recoverable_secret is None  # irreversible-cipher

    def test_get_vendor_info(self):
        assert HuaweiVRPParser().get_vendor_info().vendor_key == "huawei_vrp"


class TestFortinetParser:
    def setup_method(self):
        self.parsed = FortinetParser().parse(FORTI_CFG)

    def test_system_info(self):
        assert self.parsed.system.hostname == "FW-Edge1"

    def test_interfaces(self):
        assert len(self.parsed.interfaces) == 2
        port1 = next(i for i in self.parsed.interfaces if i.name == "port1")
        assert port1.ip_address == "5.5.5.1"
        assert port1.is_public is True

    def test_acl_rule_count(self):
        # Exactly one policy edit block → exactly one AclRule, no phantom
        # entries from "end" closing a section with no active edit.
        assert len(self.parsed.acl_rules) == 1
        assert self.parsed.acl_rules[0].action == "permit"

    def test_nat_rule_from_vip(self):
        assert len(self.parsed.nat_rules) == 1
        vip = self.parsed.nat_rules[0]
        assert vip.outside_address == "5.5.5.5"
        assert vip.inside_address == "10.10.10.5"

    def test_admin_password_never_recoverable(self):
        assert len(self.parsed.local_users) == 1
        assert self.parsed.local_users[0].recoverable_secret is None

    def test_get_vendor_info(self):
        assert FortinetParser().get_vendor_info().vendor_key == "fortinet"


class TestPaloAltoParser:
    def setup_method(self):
        self.parsed = PaloAltoParser().parse(PALOALTO_CFG)

    def test_system_info(self):
        assert self.parsed.system.hostname == "PA-Edge1"

    def test_interfaces(self):
        assert len(self.parsed.interfaces) == 2
        wan = next(i for i in self.parsed.interfaces if i.name == "ethernet1/1")
        assert wan.ip_address == "5.5.5.1"
        assert wan.netmask == "30"
        assert wan.is_public is True

    def test_route(self):
        assert len(self.parsed.routes) == 1
        assert self.parsed.routes[0].next_hop == "5.5.5.2"

    def test_address_object(self):
        assert self.parsed.object_groups[0].members == ["10.10.10.0/24"]

    def test_security_rule(self):
        assert len(self.parsed.acl_rules) == 1
        assert self.parsed.acl_rules[0].action == "permit"

    def test_nat_rule(self):
        assert self.parsed.nat_rules[0].outside_address == "5.5.5.10"

    def test_mgt_user_never_recoverable(self):
        assert self.parsed.local_users[0].recoverable_secret is None

    def test_get_vendor_info(self):
        assert PaloAltoParser().get_vendor_info().vendor_key == "paloalto"


class TestUniFiParser:
    def setup_method(self):
        self.parsed = UniFiParser().parse(UNIFI_CFG)

    def test_not_json_returns_false_on_detect(self):
        assert UniFiParser().detect("not json at all") is False

    def test_system_info(self):
        assert self.parsed.system.hostname == "USG-Edge1"

    def test_interfaces(self):
        assert len(self.parsed.interfaces) == 2
        wan = next(i for i in self.parsed.interfaces if i.name == "eth0")
        assert wan.ip_address == "5.5.5.1"
        assert wan.is_public is True

    def test_route(self):
        assert self.parsed.routes[0].next_hop == "5.5.5.2"

    def test_acl_rule(self):
        assert len(self.parsed.acl_rules) == 1
        assert self.parsed.acl_rules[0].action == "permit"

    def test_nat_rule(self):
        assert self.parsed.nat_rules[0].outside_address == "5.5.5.5"

    def test_no_local_users(self):
        assert self.parsed.local_users == []

    def test_get_vendor_info(self):
        assert UniFiParser().get_vendor_info().vendor_key == "unifi"


class TestPfSenseParser:
    def setup_method(self):
        self.parsed = PfSenseParser().parse(PFSENSE_CFG)

    def test_not_xml_returns_false_on_detect(self):
        assert PfSenseParser().detect("not xml at all") is False

    def test_system_info(self):
        assert self.parsed.system.hostname == "pfsense-edge"

    def test_interfaces(self):
        assert len(self.parsed.interfaces) == 2
        wan = next(i for i in self.parsed.interfaces if i.name == "wan")
        assert wan.ip_address == "5.5.5.1"
        assert wan.is_public is True

    def test_route(self):
        assert self.parsed.routes[0].next_hop == "WAN_GW"

    def test_acl_rule(self):
        assert len(self.parsed.acl_rules) == 1
        assert self.parsed.acl_rules[0].action == "permit"
        assert self.parsed.acl_rules[0].destination_port == "443"

    def test_nat_rule(self):
        assert self.parsed.nat_rules[0].outside_address == "5.5.5.5"

    def test_vlan(self):
        assert self.parsed.vlans[0].vlan_id == "10"
        assert self.parsed.vlans[0].name == "SALES"

    def test_local_users_never_recoverable(self):
        assert self.parsed.local_users[0].recoverable_secret is None

    def test_get_vendor_info(self):
        assert PfSenseParser().get_vendor_info().vendor_key == "pfsense"

    def test_xxe_attempt_does_not_resolve_entity(self):
        # A real pfSense config.xml never contains a DOCTYPE/ENTITY decl —
        # _try_parse rejects it outright rather than letting expat see it.
        assert PfSenseParser().detect(PFSENSE_XXE_ATTEMPT) is False
        parsed = PfSenseParser().parse(PFSENSE_XXE_ATTEMPT)
        assert parsed.system.hostname == ""
        assert "root:" not in parsed.system.hostname


class TestMacHelpers:
    def test_colon_separated(self):
        assert looks_like_mac("00:11:22:33:44:55") is True

    def test_cisco_dotted(self):
        assert looks_like_mac("0011.2233.4455") is True

    def test_dashed_pairs(self):
        assert looks_like_mac("00-11-22-33-44-55") is True

    def test_huawei_dashed_quads(self):
        assert looks_like_mac("0011-2233-4455") is True

    def test_rejects_ip(self):
        assert looks_like_mac("10.10.10.5") is False

    def test_rejects_plain_word(self):
        assert looks_like_mac("GigabitEthernet0/1") is False

    def test_normalize_to_colon_lowercase(self):
        assert normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"
        assert normalize_mac("0011-2233-4455") == "00:11:22:33:44:55"
        assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
        assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"

    def test_normalize_passthrough_for_non_mac(self):
        assert normalize_mac("10.10.10.5") == "10.10.10.5"

    def test_extract_ip_and_mac_finds_both(self):
        pair = extract_ip_and_mac(["Internet", "10.10.10.5", "23", "0022.3344.5566", "ARPA"])
        assert pair == ("10.10.10.5", "00:22:33:44:55:66")

    def test_extract_ip_and_mac_none_when_missing_mac(self):
        assert extract_ip_and_mac(["permit", "ip", "any", "any"]) is None

    def test_extract_ip_and_mac_none_when_missing_ip(self):
        assert extract_ip_and_mac(["00:11:22:33:44:55", "up"]) is None


# ── ARP tables / DHCP lease lists ──────────────────────────────────────
# Operators paste the matching command's operational-mode output into the
# same upload as the running-config; these are *observed live state*, not
# config, and are opportunistically extracted regardless of exact table
# formatting (see firewall_parsers/util.py::scan_operational_table).

IOS_ARP_DHCP = CISCO_CFG + """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.10.10.5              23   0022.3344.5566  ARPA   GigabitEthernet0/1
Internet  10.10.10.9               -   0033.4455.6677  ARPA   GigabitEthernet0/1

IP address      Client-ID/Hardware address    Lease expiration        Type
10.10.10.50     0011.2233.4455                Mar 01 2026 12:00 AM    Automatic
"""

ASA_ARP_DHCP = ASA_CFG + """
outside 203.0.113.1 0011.2233.4455 12
inside 10.10.10.5 0022.3344.5566 45

IP Address       Client Identifier or Hardware Address     Lease Expiration          Type
10.10.10.60      0011.2233.4499                             86400 seconds             Automatic
"""

MIKROTIK_ARP_DHCP = MIKROTIK_CFG + """
Flags: X - disabled, I - invalid, H - DHCP
 #    ADDRESS         MAC-ADDRESS       INTERFACE
 0 H  10.10.10.50     00:11:22:33:44:55 ether1
 1    10.10.10.5      00:22:33:44:55:66 ether1

Flags: X - disabled, R - radius
 #   ADDRESS          MAC-ADDRESS       HOST-NAME       SERVER
 0   10.10.10.51      00:AA:BB:CC:DD:EE laptop01        dhcp1
"""

HUAWEI_ARP_DHCP = HUAWEI_CFG + """
IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE       INTERFACE
10.10.10.1      0011-2233-4455  20        DYNAMIC    GigabitEthernet0/0/1

IP               MAC             LeaseExpireTime
10.10.10.52      0011-2233-9999  2026-03-01 12:00:00
"""

FORTI_ARP_DHCP = FORTI_CFG + """
Address           Age(min)   Hardware Addr        Interface
10.10.10.5        0          00:11:22:33:44:55    port1

List DHCP leased clients for port2:
    IP              MAC                 Lease Expired            Hostname
    10.10.10.53     00:11:22:33:44:88   Fri Mar  1 12:00:00 2026  laptop02
"""

PALOALTO_ARP = PALOALTO_CFG + """
interface   ip           mac                port    status
ethernet1/1 10.10.10.5   00:11:22:33:44:55  eth1/1  c
"""


class TestArpTableParsing:
    def test_cisco_ios(self):
        parsed = CiscoIOSParser().parse(IOS_ARP_DHCP)
        assert len(parsed.arp_entries) == 2
        e = next(a for a in parsed.arp_entries if a.ip == "10.10.10.5")
        assert e.mac == "00:22:33:44:55:66"
        assert e.interface == "GigabitEthernet0/1"

    def test_cisco_asa_no_header(self):
        # ASA's `show arp` prints no header row at all — row-shape
        # matching only, must not misfire on ordinary config lines.
        parsed = CiscoASAParser().parse(ASA_ARP_DHCP)
        assert len(parsed.arp_entries) == 2
        e = next(a for a in parsed.arp_entries if a.ip == "10.10.10.5")
        assert e.mac == "00:22:33:44:55:66"
        assert e.interface == "inside"

    def test_mikrotik(self):
        parsed = MikroTikParser().parse(MIKROTIK_ARP_DHCP)
        assert len(parsed.arp_entries) == 2
        e = next(a for a in parsed.arp_entries if a.ip == "10.10.10.50")
        assert e.mac == "00:11:22:33:44:55"
        assert e.interface == "ether1"

    def test_mikrotik_dhcp_header_does_not_leak_into_arp(self):
        # The DHCP-lease header shares two of the ARP header's three
        # column names — must not also be picked up as an ARP block.
        parsed = MikroTikParser().parse(MIKROTIK_ARP_DHCP)
        assert all(a.ip != "10.10.10.51" for a in parsed.arp_entries)

    def test_huawei(self):
        parsed = HuaweiVRPParser().parse(HUAWEI_ARP_DHCP)
        assert len(parsed.arp_entries) == 1
        assert parsed.arp_entries[0].mac == "00:11:22:33:44:55"

    def test_fortinet(self):
        parsed = FortinetParser().parse(FORTI_ARP_DHCP)
        assert len(parsed.arp_entries) == 1
        assert parsed.arp_entries[0].interface == "port1"

    def test_paloalto(self):
        parsed = PaloAltoParser().parse(PALOALTO_ARP)
        assert len(parsed.arp_entries) == 1
        assert parsed.arp_entries[0].mac == "00:11:22:33:44:55"


class TestDhcpLeaseParsing:
    def test_cisco_ios_no_hostname_column(self):
        parsed = CiscoIOSParser().parse(IOS_ARP_DHCP)
        assert len(parsed.dhcp_leases) == 1
        assert parsed.dhcp_leases[0].ip == "10.10.10.50"
        assert parsed.dhcp_leases[0].hostname == ""

    def test_cisco_asa(self):
        parsed = CiscoASAParser().parse(ASA_ARP_DHCP)
        assert len(parsed.dhcp_leases) == 1
        assert parsed.dhcp_leases[0].mac == "00:11:22:33:44:99"

    def test_mikrotik_captures_hostname(self):
        parsed = MikroTikParser().parse(MIKROTIK_ARP_DHCP)
        assert len(parsed.dhcp_leases) == 1
        assert parsed.dhcp_leases[0].hostname == "laptop01"

    def test_huawei_no_hostname_column(self):
        parsed = HuaweiVRPParser().parse(HUAWEI_ARP_DHCP)
        assert len(parsed.dhcp_leases) == 1
        assert parsed.dhcp_leases[0].mac == "00:11:22:33:99:99"

    def test_fortinet_captures_hostname(self):
        parsed = FortinetParser().parse(FORTI_ARP_DHCP)
        assert len(parsed.dhcp_leases) == 1
        assert parsed.dhcp_leases[0].hostname == "laptop02"

    def test_paloalto_not_implemented(self):
        # PAN-OS doesn't have a standard DHCP-server-lease export the way
        # the others do — arp_entries only, dhcp_leases stays empty.
        parsed = PaloAltoParser().parse(PALOALTO_ARP)
        assert parsed.dhcp_leases == []
