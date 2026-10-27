"""Extended tests for scan_helpers — donpapi and httpx helpers."""
import pytest
from unittest.mock import MagicMock, patch

from app.core.scan_helpers import (
    httpx_upsert_host,
    ffuf_severity,
    ffuf_upsert_finding,
    cme_build_auth,
    donpapi_upsert_cred,
    _donpapi_build_fetch_cmd,
)


class TestHttpxUpsertHost:
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"host": "10.0.0.1", "port": 443}
        result = httpx_upsert_host(db, "p1", r)
        assert result.ip == "10.0.0.1"
        db.add.assert_called()

    def test_existing_by_ip(self):
        existing = MagicMock()
        existing.deleted_at = None
        existing.ports = []
        existing.services = []
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r = {"host": "10.0.0.1", "port": 443}
        result = httpx_upsert_host(db, "p1", r)
        assert result is existing

    def test_existing_by_hostname(self):
        existing = MagicMock()
        existing.deleted_at = None
        existing.ports = []
        existing.services = []
        db = MagicMock()
        db.query.return_value.filter.return_value.first.side_effect = [None, existing]
        r = {"host": "web01", "port": 80}
        result = httpx_upsert_host(db, "p1", r)
        assert result is existing


class TestFfufSeverity:
    def test_200_low(self):
        assert ffuf_severity(200, "/page") == "low"

    def test_204_low(self):
        assert ffuf_severity(204, "/page") == "low"

    def test_admin_medium(self):
        assert ffuf_severity(403, "/admin") == "medium"

    def test_env_medium(self):
        assert ffuf_severity(200, "/.env") == "medium"

    def test_default_info(self):
        assert ffuf_severity(404, "/page") == "info"

    def test_secret_medium(self):
        assert ffuf_severity(200, "/secret") == "medium"

    def test_backup_medium(self):
        assert ffuf_severity(200, "/backup.sql") == "medium"

    def test_passwd_medium(self):
        assert ffuf_severity(200, "/etc/passwd") == "medium"

    def test_config_medium(self):
        assert ffuf_severity(200, "/config.yml") == "medium"


class TestFfufUpsertFinding:
    def test_new_finding(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin", "length": 100, "words": 50}
        result = ffuf_upsert_finding(db, "p1", r, "http://x", "2025-01-01")
        assert result is True
        db.add.assert_called()

    def test_existing_finding(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        result = ffuf_upsert_finding(db, "p1", {"status": 200, "url": "http://x/a"}, "http://x", "ts")
        assert result is False


class TestCmeBuildAuth:
    def test_with_hash(self):
        result = cme_build_auth({"hash": "nthash", "username": "admin"})
        assert "-H nthash" in result

    def test_with_password(self):
        result = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-u admin" in result
        assert "-p pass" in result

    def test_username_only(self):
        result = cme_build_auth({"username": "admin"})
        assert "-u admin" in result

    def test_empty(self):
        assert cme_build_auth({}) == ""


class TestDonpapiUpsertCred:
    def test_new_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        encrypt_fn = lambda x: f"enc_{x}"
        cred = {"username": "admin", "secret": "pass", "service": "smb",
                "domain": "dom", "host_hint": "10.0.0.1", "kind": "dpapi"}
        result = donpapi_upsert_cred(db, "p1", cred, "10.0.0.1", encrypt_fn)
        assert result is True

    def test_existing_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        result = donpapi_upsert_cred(db, "p1", {"username": "a", "secret": "s",
                                                  "service": "smb"}, "t", lambda x: x)
        assert result is False


class TestDonpapiBuildFetchCmd:
    def test_basic(self):
        cmd = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in cmd
        assert "/tmp/output" in cmd
        assert "base64" in cmd


class TestMergePorts:
    def test_numeric_order_and_dedup(self):
        from app.core.scan_helpers import merge_ports
        out = merge_ports(["443/tcp", "80/tcp"], ["22/tcp", "80/tcp", "8080/tcp"])
        assert out == ["22/tcp", "80/tcp", "443/tcp", "8080/tcp"]

    def test_tcp_and_udp_same_port_coexist(self):
        from app.core.scan_helpers import merge_ports
        assert merge_ports(["443/tcp"], ["443/udp"]) == ["443/tcp", "443/udp"]

    def test_none_inputs(self):
        from app.core.scan_helpers import merge_ports
        assert merge_ports(None, None) == []
        assert merge_ports(None, ["22/tcp"]) == ["22/tcp"]

    def test_order_is_stable_across_rescans(self):
        from app.core.scan_helpers import merge_ports
        first = merge_ports([], ["8080/tcp", "22/tcp", "443/tcp"])
        again = merge_ports(first, ["22/tcp", "443/tcp", "8080/tcp"])
        assert first == again == ["22/tcp", "443/tcp", "8080/tcp"]


class TestMergeServices:
    def test_version_label_wins_over_bare(self):
        from app.core.scan_helpers import merge_services
        # A bare re-scan must NOT duplicate the port's service entry.
        out = merge_services(["22/ssh (OpenSSH 8.2p1)"], ["22/ssh"])
        assert out == ["22/ssh (OpenSSH 8.2p1)"]

    def test_richer_label_replaces_bare(self):
        from app.core.scan_helpers import merge_services
        out = merge_services(["22/ssh"], ["22/ssh (OpenSSH 8.2p1)"])
        assert out == ["22/ssh (OpenSSH 8.2p1)"]

    def test_sorted_by_port(self):
        from app.core.scan_helpers import merge_services
        out = merge_services([], ["443/https", "22/ssh", "80/http"])
        assert out == ["22/ssh", "80/http", "443/https"]


class TestNmapUpsertRescanMerge:
    def test_rescan_keeps_order_and_no_dup_services(self):
        from app.core.scan_helpers import nmap_upsert_host
        existing = MagicMock()
        existing.deleted_at = None
        existing.ports = ["80/tcp", "22/tcp"]
        existing.services = ["22/ssh (OpenSSH 8.2p1)", "80/http"]
        existing.hostname = "web01"
        existing.os = "Linux"
        existing.import_source = "nmap"
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "", "os": "",
             "ports": ["22/tcp", "443/tcp"], "services": ["22/ssh", "443/https"]}
        host, was_new = nmap_upsert_host(db, "p1", h)
        assert was_new is False
        assert host.ports == ["22/tcp", "80/tcp", "443/tcp"]
        # 22/ssh must not be duplicated; the version-bearing label is kept.
        assert host.services == ["22/ssh (OpenSSH 8.2p1)", "80/http", "443/https"]
