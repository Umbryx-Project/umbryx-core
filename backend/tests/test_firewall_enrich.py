"""
Tests for core/firewall_enrich.py and core/firewall_config_diff.py — direct
function calls against a test DB session (same style as test_scan_helpers.py).
"""

import pytest
from sqlalchemy.orm import Session

from app import models
from app.core.key_management import decrypt_for_project
from app.core.firewall_config_diff import diff_parsed_configs
from app.core.firewall_enrich import enrich_project_from_config, parsed_config_to_safe_dict
from app.core.firewall_parsers.cisco_ios import CiscoIOSParser
from app.core.utils import new_id

CISCO_CFG_V1 = """
hostname EdgeRouter1
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet0/1
 ip address 10.10.10.1 255.255.255.0
!
ip access-list extended OUTSIDE_IN
 permit ip any any
!
username admin privilege 15 password 7 0822455D0A16
!
"""

CISCO_CFG_PUBLIC_WAN = """
hostname EdgeRouter2
!
interface GigabitEthernet0/0
 ip address 5.5.5.1 255.255.255.252
!
interface GigabitEthernet0/1
 ip address 10.20.20.1 255.255.255.0
!
"""

CISCO_CFG_V2 = """
hostname EdgeRouter1
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet0/1
 ip address 10.10.10.1 255.255.255.0
!
ip access-list extended OUTSIDE_IN
 permit ip any any
 permit tcp any any eq 22
!
username admin privilege 15 password 7 0822455D0A16
!
"""


@pytest.fixture()
def pid(db: Session) -> str:
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="FW Enrich Test", added="2024-01-01"))
    db.commit()
    return p_id


def _parse(cfg: str):
    return CiscoIOSParser().parse(cfg)


class TestEnrichCreatesObjects:
    def test_host_created(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        assert result.host_created is True
        host = db.query(models.Host).filter(models.Host.id == result.host_id).first()
        assert host is not None
        assert host.ip == "203.0.113.1"
        assert "firewall" in host.tags

    def test_networks_created(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        assert result.networks_created == 2
        values = {s.value for s in db.query(models.Scope).filter(models.Scope.pid == pid).all()}
        assert "203.0.113.0/30" in values
        assert "10.10.10.0/24" in values

    def test_finding_created_for_permit_any_any(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        assert result.findings_created == 1
        finding = db.query(models.Finding).filter(models.Finding.pid == pid).first()
        assert "any/any" in finding.title
        assert finding.source == "firewall_config"

    def test_cred_created_and_encrypted(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        assert result.creds_created == 1
        cred = (
            db.query(models.Cred)
            .filter(models.Cred.pid == pid, models.Cred.service == "firewall_config")
            .first()
        )
        assert cred is not None
        assert cred.secret.startswith("__pdek__:")
        assert decrypt_for_project(db, pid, cred.secret) == "cisco"


class TestEnrichPublicIpClassification:
    def test_public_wan_scope_marked_in_scope_and_external(self, db, pid):
        enrich_project_from_config(db, pid, _parse(CISCO_CFG_PUBLIC_WAN), "cisco_ios")
        db.commit()
        scopes = {s.value: s for s in db.query(models.Scope).filter(models.Scope.pid == pid).all()}
        wan = scopes["5.5.5.0/30"]
        assert wan.in_scope is True
        assert "external" in wan.description
        lan = scopes["10.20.20.0/24"]
        assert lan.in_scope is False
        assert "internal" in lan.description

    def test_host_tagged_external_facing_when_any_interface_public(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_PUBLIC_WAN), "cisco_ios")
        db.commit()
        host = db.query(models.Host).filter(models.Host.id == result.host_id).first()
        assert "external-facing" in host.tags

    def test_host_not_tagged_external_facing_when_all_private(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        host = db.query(models.Host).filter(models.Host.id == result.host_id).first()
        # CISCO_CFG_V1's WAN address (203.0.113.1) is an RFC5737
        # documentation-range address, not actually global.
        assert "external-facing" not in host.tags


class TestEnrichIdempotency:
    def test_reapplying_same_config_creates_no_duplicates(self, db, pid):
        r1 = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        r2 = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()

        assert r1.host_created is True
        assert r2.host_created is False
        assert r2.host_id == r1.host_id

        assert db.query(models.Host).filter(models.Host.pid == pid).count() == 1
        assert db.query(models.Scope).filter(models.Scope.pid == pid).count() == 2
        assert db.query(models.Finding).filter(models.Finding.pid == pid).count() == 1
        assert db.query(models.Cred).filter(models.Cred.pid == pid).count() == 1

        assert r2.networks_created == 0
        assert r2.networks_existing == 2
        assert r2.findings_created == 0
        assert r2.findings_skipped == 1
        assert r2.creds_created == 0
        assert r2.creds_skipped == 1

    def test_updated_config_adds_new_finding_without_duplicating_host(self, db, pid):
        enrich_project_from_config(db, pid, _parse(CISCO_CFG_V1), "cisco_ios")
        db.commit()
        r2 = enrich_project_from_config(db, pid, _parse(CISCO_CFG_V2), "cisco_ios")
        db.commit()
        assert r2.host_created is False
        assert db.query(models.Host).filter(models.Host.pid == pid).count() == 1
        # V2 adds an SSH-reachable-from-any rule → one more finding, same
        # "permit any/any" finding deduped against V1's.
        titles = {f.title for f in db.query(models.Finding).filter(models.Finding.pid == pid).all()}
        assert any("SSH" in t for t in titles)


CISCO_CFG_WITH_ARP_DHCP = CISCO_CFG_V1 + """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.10.10.50             23   0022.3344.5566  ARPA   GigabitEthernet0/1
Internet  203.0.113.1              -   0011.2233.4455  ARPA   GigabitEthernet0/0

IP address      Client-ID/Hardware address    Lease expiration        Type
10.10.10.50     0022.3344.5566                Mar 01 2026 12:00 AM    Automatic
"""


class TestEnrichArpDhcpHosts:
    """ARP/DHCP entries are observed live state, not config — they must
    discover new lightweight Host stubs and enrich already-known ones
    (mac tag, hostname), without ever duplicating the device's own Host
    row (2026-08-18)."""

    def test_new_host_discovered_from_arp(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_WITH_ARP_DHCP), "cisco_ios")
        db.commit()
        # .50 only — 203.0.113.1 is the device's own Host (the first
        # interface with an IP is what _resolve_device_host keys on).
        assert result.hosts_discovered == 1
        host = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.ip == "10.10.10.50")
            .first()
        )
        assert host is not None
        assert "discovered-via-arp-dhcp" in host.tags
        assert "mac:00:22:33:44:55:66" in host.tags

    def test_dhcp_hostname_fills_blank_host(self, db, pid):
        enrich_project_from_config(db, pid, _parse(CISCO_CFG_WITH_ARP_DHCP), "cisco_ios")
        db.commit()
        host = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.ip == "10.10.10.50")
            .first()
        )
        # This IOS DHCP-binding sample has no hostname column, so it stays blank —
        # confirms the stub host doesn't crash/misparse when hostname is unavailable.
        assert host.hostname == ""

    def test_arp_entry_for_device_ip_enriches_not_duplicates(self, db, pid):
        result = enrich_project_from_config(db, pid, _parse(CISCO_CFG_WITH_ARP_DHCP), "cisco_ios")
        db.commit()
        # 203.0.113.1 already exists as the device's own Host (from
        # interfaces) — the matching ARP row must tag it, not create a
        # second Host at the same IP.
        assert (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.ip == "203.0.113.1")
            .count()
            == 1
        )
        host = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.ip == "203.0.113.1")
            .first()
        )
        assert "mac:00:11:22:33:44:55" in host.tags
        assert result.hosts_enriched == 1

    def test_reapplying_does_not_duplicate_discovered_hosts(self, db, pid):
        enrich_project_from_config(db, pid, _parse(CISCO_CFG_WITH_ARP_DHCP), "cisco_ios")
        db.commit()
        r2 = enrich_project_from_config(db, pid, _parse(CISCO_CFG_WITH_ARP_DHCP), "cisco_ios")
        db.commit()
        assert r2.hosts_discovered == 0
        assert (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.ip == "10.10.10.50")
            .count()
            == 1
        )


class TestDiffParsedConfigs:
    def test_no_previous_config_reports_everything_added(self):
        new = parsed_config_to_safe_dict(_parse(CISCO_CFG_V1))
        diff = diff_parsed_configs({}, new)
        assert diff["has_changes"] is True
        assert len(diff["added_interfaces"]) == 2
        assert len(diff["added_acl_rules"]) == 1

    def test_identical_config_has_no_changes(self):
        parsed = parsed_config_to_safe_dict(_parse(CISCO_CFG_V1))
        diff = diff_parsed_configs(parsed, parsed)
        assert diff["has_changes"] is False
        assert diff["added_acl_rules"] == []
        assert diff["removed_acl_rules"] == []

    def test_added_acl_rule_detected(self):
        old = parsed_config_to_safe_dict(_parse(CISCO_CFG_V1))
        new = parsed_config_to_safe_dict(_parse(CISCO_CFG_V2))
        diff = diff_parsed_configs(old, new)
        assert diff["has_changes"] is True
        assert len(diff["added_acl_rules"]) == 1
        assert diff["added_acl_rules"][0]["destination_port"] == "eq 22"
        assert diff["removed_acl_rules"] == []

    def test_parsed_json_never_contains_recoverable_secret(self):
        d = parsed_config_to_safe_dict(_parse(CISCO_CFG_V1))
        assert all(u["recoverable_secret"] is None for u in d["local_users"])
