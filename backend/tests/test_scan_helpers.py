"""Consolidated tests for test_scan_helpers (merged variant files)."""

# ════════ from test_scan_helpers_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.core.scan_helpers import (
    cme_upsert_host,
    cme_upsert_cred,
    cme_build_auth,
    cme_process_hosts,
    cme_process_creds,
    httpx_upsert_host,
    ffuf_severity,
    ffuf_upsert_finding,
    donpapi_upsert_cred,
    _donpapi_build_fetch_cmd,
)


class TestCmeUpsertHost_final:
    def test_existing(self):
        db = MagicMock()
        existing = MagicMock()
        existing.hostname = ""
        existing.ports = ["22/tcp"]
        existing.deleted_at = None
        existing.services = ["ssh"]
        existing.import_source = ""
        db.query.return_value.filter.return_value.first.return_value = existing
        host, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "hostname": "SRV1", "ports": ["445/tcp"], "services": ["smb"]})
        assert created is False
        assert existing.hostname == "SRV1"

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        host, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "hostname": "", "ports": [], "services": []})
        assert created is True


class TestCmeUpsertCred_final:
    def test_existing_key(self):
        db = MagicMock()
        result = cme_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "corp", {("admin", "smb")})
        assert result[0] is None

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = cme_upsert_cred(db, "p1", {"username": "admin", "secret": "pass", "type": "plain", "service": "smb"}, "corp", set())
        assert result[0] is not None
        assert result[1] is True


class TestCmeBuildAuth_final:
    def test_hash(self):
        result = cme_build_auth({"hash": "AADM123", "username": "admin"})
        assert "-H" in result

    def test_user_pass(self):
        result = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-u" in result
        assert "-p" in result

    def test_user_only(self):
        result = cme_build_auth({"username": "admin"})
        assert "-u" in result

    def test_empty(self):
        assert cme_build_auth({}) == ""


class TestCmeProcessHosts_final:
    def test_process(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_host", return_value=(MagicMock(), True)):
            hosts, domains, created = cme_process_hosts(db, "p1", [{"ip": "10.0.0.1", "domain": "corp"}])
            assert created == 1
            assert "10.0.0.1" in domains


class TestCmeProcessCreds_final:
    def test_process(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_cred", return_value=(MagicMock(), True)):
            creds, created = cme_process_creds(db, "p1", [{"username": "admin"}], "corp", set())
            assert created == 1


class TestHttpxUpsertHost_final:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        host = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": "443/tcp"})
        assert host is not None

    def test_existing_by_ip(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        db.query.return_value.filter.return_value.first.return_value = existing
        host = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": "80/tcp"})
        assert host == existing

    def test_existing_by_hostname(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        db.query.return_value.filter.return_value.first.side_effect = [None, existing]
        host = httpx_upsert_host(db, "p1", {"host": "srv1.example.com", "port": "443/tcp"})
        assert host == existing


class TestFfufSeverity_final:
    def test_200(self):
        assert ffuf_severity(200, "/path") == "low"

    def test_204(self):
        assert ffuf_severity(204, "/path") == "low"

    def test_sensitive_path(self):
        assert ffuf_severity(200, "/admin") == "medium"

    def test_env_path(self):
        assert ffuf_severity(200, "/.env") == "medium"

    def test_default(self):
        assert ffuf_severity(403, "/normal") == "info"


class TestFfufUpsertFinding_final:
    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert ffuf_upsert_finding(db, "p1", {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin"}, "http://x", "ts") is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert ffuf_upsert_finding(db, "p1", {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin", "length": 100, "words": 50}, "http://x", "ts") is True


class TestDonpapiUpsertCred_final:
    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "", "service": "smb", "secret": "x", "kind": "dpapi"}, "10.0.0.1", lambda x: x) is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "", "service": "smb", "secret": "x", "kind": "dpapi", "host_hint": "10.0.0.1"}, "10.0.0.1", lambda x: x) is True


class TestDonpapiBuildFetchCmd_final:
    def test_basic(self):
        result = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in result
        assert "base64" in result


# ════════ from test_scan_helpers_final2.py ════════
import pytest
from unittest.mock import MagicMock

from app.core.scan_helpers import (
    nmap_upsert_host,
    cme_upsert_host,
    cme_upsert_cred,
    cme_build_auth,
    cme_process_hosts,
    cme_process_creds,
    httpx_upsert_host,
    ffuf_severity,
    ffuf_upsert_finding,
    donpapi_upsert_cred,
    _donpapi_build_fetch_cmd,
)


class TestNmapUpsertHost_final2:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        h = {"ip": "10.0.0.1", "hostname": "srv", "os": "Linux", "ports": ["80/tcp"], "services": ["http"]}
        host, created = nmap_upsert_host(db, "p1", h)
        assert created is True
        assert db.add.called

    def test_existing(self):
        existing = MagicMock()
        existing.ports = ["443/tcp"]
        existing.deleted_at = None
        existing.services = ["https"]
        existing.hostname = ""
        existing.os = ""
        existing.status = "down"
        existing.import_source = ""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "srv", "os": "Linux", "ports": ["80/tcp"], "services": ["http"]}
        host, created = nmap_upsert_host(db, "p1", h)
        assert created is False
        assert "80/tcp" in existing.ports
        assert existing.status == "up"

    def test_existing_no_override(self):
        existing = MagicMock()
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        existing.hostname = "existing"
        existing.os = "Windows"
        existing.status = "up"
        existing.import_source = "manual"
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "new", "os": "Linux", "ports": [], "services": []}
        nmap_upsert_host(db, "p1", h)
        assert existing.hostname == "existing"
        assert existing.os == "Windows"


class TestCmeUpsertHost_final2:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        h = {"ip": "10.0.0.1", "hostname": "srv", "ports": ["445/tcp"], "services": ["smb"]}
        host, created = cme_upsert_host(db, "p1", h)
        assert created is True

    def test_existing(self):
        existing = MagicMock()
        existing.hostname = ""
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        existing.import_source = ""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "srv", "ports": ["445/tcp"], "services": ["smb"]}
        host, created = cme_upsert_host(db, "p1", h)
        assert created is False
        assert existing.hostname == "srv"


class TestCmeUpsertCred_final2:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        c = {"username": "admin", "secret": "pass", "type": "plain", "service": "smb"}
        cred, created = cme_upsert_cred(db, "p1", c, "corp", set())
        assert created is True
        assert db.add.called

    def test_duplicate(self):
        db = MagicMock()
        c = {"username": "admin", "service": "smb"}
        cred, created = cme_upsert_cred(db, "p1", c, "corp", {("admin", "smb")})
        assert created is False


class TestCmeBuildAuth_final2:
    def test_hash(self):
        r = cme_build_auth({"hash": "abc123", "username": "admin"})
        assert "-H abc123" in r

    def test_password(self):
        r = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-p pass" in r

    def test_username_only(self):
        r = cme_build_auth({"username": "admin"})
        assert "-u admin" in r

    def test_empty(self):
        assert cme_build_auth({}) == ""


class TestCmeProcessHosts_final2:
    def test_basic(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        hosts = [{"ip": "10.0.0.1", "hostname": "srv", "domain": "corp",
                  "ports": ["445/tcp"], "services": ["smb"]}]
        objs, domains, created = cme_process_hosts(db, "p1", hosts)
        assert created == 1
        assert domains["10.0.0.1"] == "corp"

    def test_empty(self):
        db = MagicMock()
        objs, domains, created = cme_process_hosts(db, "p1", [])
        assert created == 0


class TestCmeProcessCreds_final2:
    def test_basic(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        creds = [{"username": "admin", "secret": "pass"}]
        objs, created = cme_process_creds(db, "p1", creds, "corp", set())
        assert created == 1


class TestHttpxUpsertHost_final2:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"host": "10.0.0.1", "port": "8080/tcp"}
        host = httpx_upsert_host(db, "p1", r)
        assert db.add.called

    def test_existing_add_port(self):
        existing = MagicMock()
        existing.ports = ["80/tcp"]
        existing.deleted_at = None
        existing.services = ["http"]
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r = {"host": "10.0.0.1", "port": "443/tcp"}
        httpx_upsert_host(db, "p1", r)
        assert "443/tcp" in existing.ports
        assert "https" in existing.services

    def test_hostname_match(self):
        existing = MagicMock()
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.query.return_value.filter.return_value.first.side_effect = [None, existing]
        r = {"host": "srv01.example.com", "port": "80/tcp"}
        host = httpx_upsert_host(db, "p1", r)


class TestFfufSeverity_final2:
    def test_200(self):
        assert ffuf_severity(200, "") == "low"

    def test_404(self):
        assert ffuf_severity(404, "") == "info"

    def test_sensitive_path(self):
        assert ffuf_severity(200, "/admin") == "medium"
        assert ffuf_severity(200, "/.env") == "medium"

    def test_normal_path(self):
        assert ffuf_severity(200, "/page") == "low"


class TestFfufUpsertFinding_final2:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"status": 200, "url": "http://target/admin", "input": {"FUZZ": "admin"},
             "length": 1024, "words": 200}
        assert ffuf_upsert_finding(db, "p1", r, "http://target", "ts") is True
        assert db.add.called

    def test_existing(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r = {"status": 200, "url": "http://target/admin", "input": {"FUZZ": "admin"}}
        assert ffuf_upsert_finding(db, "p1", r, "http://target", "ts") is False


class TestDonpapiUpsertCred_final2:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        cred = {"username": "admin", "domain": "corp", "service": "smb",
                "secret": "pass", "kind": "dpapi", "host_hint": "10.0.0.1"}
        assert donpapi_upsert_cred(db, "p1", cred, "10.0.0.1", lambda x: f"enc:{x}") is True

    def test_existing(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "t", lambda x: x) is False


class TestDonpapiBuildFetchCmd_final2:
    def test_basic(self):
        r = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in r
        assert "/tmp/output" in r


# ════════ from test_scan_helpers_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.core.scan_helpers import (
    nmap_upsert_host,
    cme_upsert_host,
    cme_upsert_cred,
    cme_build_auth,
    cme_process_hosts,
    cme_process_creds,
    httpx_upsert_host,
    ffuf_severity,
    ffuf_upsert_finding,
    donpapi_upsert_cred,
    _donpapi_build_fetch_cmd,
)


class TestNmapUpsertHost_v3:
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h, created = nmap_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [22], "services": ["ssh"], "hostname": "srv", "os": "Linux"})
            assert created is True
            assert db.add.called

    def test_existing_host(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = [80]
        existing.deleted_at = None
        existing.services = ["http"]
        existing.hostname = ""
        existing.os = ""
        existing.import_source = ""
        db.query.return_value.filter.return_value.first.return_value = existing
        h, created = nmap_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [22], "services": ["ssh"], "hostname": "srv", "os": "Linux"})
        assert created is False
        assert 22 in existing.ports
        assert existing.hostname == "srv"

    def test_existing_with_hostname(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        existing.hostname = "existing_name"
        existing.os = "Unknown"
        existing.import_source = "nmap"
        db.query.return_value.filter.return_value.first.return_value = existing
        h, created = nmap_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [], "services": [], "hostname": "new", "os": "Win"})
        assert existing.hostname == "existing_name"


class TestCmeUpsertHost_v3:
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [445], "services": ["smb"], "hostname": "dc"})
            assert created is True

    def test_existing_host(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.deleted_at = None
        existing.services = []
        existing.hostname = ""
        existing.import_source = ""
        db.query.return_value.filter.return_value.first.return_value = existing
        h, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [445], "services": ["smb"], "hostname": "dc"})
        assert created is False
        assert existing.hostname == "dc"


class TestCmeUpsertCred_v3:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="crd1"):
            c, created = cme_upsert_cred(db, "p1", {"username": "admin", "secret": "pass"}, "corp", set())
            assert created is True
            assert db.add.called

    def test_duplicate(self):
        db = MagicMock()
        c, created = cme_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "corp", {("admin", "smb")})
        assert created is False


class TestCmeBuildAuth_v3:
    def test_hash(self):
        r = cme_build_auth({"hash": "abc123", "username": "admin"})
        assert "-H" in r
        assert "admin" in r

    def test_password(self):
        r = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-p" in r

    def test_username_only(self):
        r = cme_build_auth({"username": "admin"})
        assert "-u" in r

    def test_empty(self):
        r = cme_build_auth({})
        assert r == ""


class TestCmeProcessHosts_v3:
    def test_basic(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_host", return_value=(MagicMock(), True)):
            hosts, domains, created = cme_process_hosts(db, "p1", [{"ip": "10.0.0.1", "domain": "corp", "ports": [], "services": []}])
            assert created == 1
            assert domains["10.0.0.1"] == "corp"


class TestCmeProcessCreds_v3:
    def test_basic(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_cred", return_value=(MagicMock(), True)):
            creds, created = cme_process_creds(db, "p1", [{"username": "admin"}], "corp", set())
            assert created == 1


class TestHttpxUpsertHost_v3:
    def test_new_by_ip(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": 443})
            assert db.add.called

    def test_existing(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = [80]
        existing.deleted_at = None
        existing.services = ["http"]
        db.query.return_value.filter.return_value.first.return_value = existing
        h = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": 443})
        assert 443 in existing.ports

    def test_http_port(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": 8080})
            assert db.add.called


class TestFfufSeverity_v3:
    def test_200(self):
        assert ffuf_severity(200, "/foo") == "low"

    def test_204(self):
        assert ffuf_severity(204, "/foo") == "low"

    def test_admin_path(self):
        assert ffuf_severity(200, "/admin") == "medium"

    def test_config_path(self):
        assert ffuf_severity(403, "/.env") == "medium"

    def test_normal(self):
        assert ffuf_severity(403, "/foo") == "info"


class TestFfufUpsertFinding_v3:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="f1"):
            r = ffuf_upsert_finding(db, "p1", {"status": 200, "url": "http://x/admin", "input": {}, "length": 100, "words": 50}, "http://x", "ts")
            assert r is True

    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        r = ffuf_upsert_finding(db, "p1", {"status": 200, "url": "http://x/admin", "input": {}}, "http://x", "ts")
        assert r is False


class TestDonpapiUpsertCred_v3:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="c1"):
            r = donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "corp", "service": "smb", "secret": "pass"}, "10.0.0.1", lambda x: x)
            assert r is True

    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        r = donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "corp", "service": "smb", "secret": "pass"}, "10.0.0.1", lambda x: x)
        assert r is False


class TestDonpapiBuildFetchCmd_v3:
    def test_basic(self):
        cmd = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in cmd
        assert "/tmp/output" in cmd


class TestSoftDeletedResurrect:
    """Regression: scan upserts must not merge into soft-deleted hosts.
    Live case: operator deletes hosts, rescans a single port — old ports
    from before the deletion reappeared (merge into the tombstone)."""

    def _host(self, db, pid, ip, ports):
        from app.core.utils import new_id, ts_now
        from app.models import Host, Project

        db.add(Project(id=pid, name=f"res-{ip}", status="active", added=ts_now()))
        db.commit()

        h = Host(id=new_id("hst"), pid=pid, ip=ip, hostname="", os="",
                 status="up", ports=ports, services=[], tags=["nmap"],
                 deleted_at=None)
        db.add(h)
        db.commit()
        return h

    def test_resurrect_replaces_ports(self, db):
        from app.core.scan_helpers import nmap_upsert_host
        from app.core.utils import new_id

        pid = new_id("p")
        h = self._host(db, pid, "10.0.0.5", ["22/tcp", "80/tcp", "443/tcp"])
        h.deleted_at = "2026-10-21T00:00:00Z"
        db.commit()

        obj, created = nmap_upsert_host(db, pid, {
            "ip": "10.0.0.5", "hostname": "", "os": "Linux",
            "ports": ["22/tcp"], "services": [],
        })
        assert created is True
        assert obj.deleted_at is None
        assert obj.ports == ["22/tcp"]  # старые 80/443 не воскресли

    def test_live_host_still_merges(self, db):
        from app.core.scan_helpers import nmap_upsert_host
        from app.core.utils import new_id

        pid = new_id("p")
        self._host(db, pid, "10.0.0.6", ["22/tcp"])
        obj, created = nmap_upsert_host(db, pid, {
            "ip": "10.0.0.6", "hostname": "", "os": "Linux",
            "ports": ["80/tcp"], "services": [],
        })
        assert created is False
        assert sorted(obj.ports) == ["22/tcp", "80/tcp"]


class TestObservationResurrect:
    """Observation apply must not INSERT over a soft-deleted host —
    (pid, ip) is UNIQUE; resurrect instead (same semantics as scan upserts)."""

    def test_observation_resurrects_tombstone(self, db):
        from app.core.scan_helpers import nmap_upsert_host  # noqa: F401
        from app.core.termtrack.enrich import _apply_host
        from app.core.utils import new_id, ts_now
        from app.models import Host, Observation, Project

        pid = new_id("p")
        db.add(Project(id=pid, name="obs-res", status="active", added=ts_now()))
        from app.models import OperatorWorkstation

        db.commit()
        db.add(OperatorWorkstation(id="ws1", name="obs-ws", status="ready", access_address="10.9.9.9", created_at=ts_now(), is_pool=True))
        db.commit()
        db.add(Host(id=new_id("hst"), pid=pid, ip="10.0.0.9", hostname="", os="",
                    status="up", ports=["445/tcp"], services=[], tags=[],
                    deleted_at="2026-10-22T00:00:00Z"))
        obs = Observation(
            id=new_id("obs"), pid=pid, workstation_id="ws1", session_id=None,
            action_id=None, tool="nmap", kind="host", status="pending",
            data={"ip": "10.0.0.9", "ports": ["22/tcp"]},
            confidence="direct", dedup_hash=new_id("h"), observed_at=ts_now(),
            provenance={},
        )
        db.add(obs)
        db.commit()

        report = _apply_host(db, obs)
        db.refresh(obs)
        row = db.query(Host).filter(Host.pid == pid, Host.ip == "10.0.0.9").one()
        assert row.deleted_at is None
        # старые удалённые порты не воскресают; живёт то, что увидели
        assert "445/tcp" not in (row.ports or [])
        assert report.get("changed") or obs.status == "applied"


class TestPortNormalization:
    """Frontend parsers emit bare port numbers ('22'); the canonical form
    is '22/tcp'. batch import must normalize at the boundary or ports
    merge in twice ('22' + '22/tcp' in one row)."""

    def test_norm_ports(self):
        from app.routers.import_export import _norm_ports

        assert _norm_ports(["22", "80/tcp", "53", "22", ""]) == ["22/tcp", "80/tcp", "53/tcp"]
        assert _norm_ports(None) == []


class TestServiceNormalization:
    def test_norm_services(self):
        from app.routers.import_export import _norm_services

        # сирота-фолбэк + голый дубликат рядом с богатым → выравниваются
        out = _norm_services(
            ["22/tcp", "53/tcp"],
            ["22/ssh (OpenSSH 8.2p1)", "53/domain (ISC BIND 9.18)", "SSH"],
        )
        assert out == ["22/ssh (OpenSSH 8.2p1)", "53/domain (ISC BIND 9.18)"]

        out = _norm_services(
            ["443/tcp"],
            ["443/https", "443/ssl/http (Apache httpd 2.4.58)"],
        )
        assert out == ["443/ssl/http (Apache httpd 2.4.58)"]

        # непрефиксованные парятся по индексу
        out = _norm_services(["21/tcp", "22/tcp"], ["ftp (ProFTPD)", "ssh"])
        assert out == ["21/ftp (ProFTPD)", "22/ssh"]

        # немаппируемые сироты отбрасываются
        assert _norm_services(["80/tcp"], ["http", "SSH", "HTTPS"]) == ["80/http"]


class TestCmeResurrect:
    """cme_upsert_host: same tombstone semantics as nmap (see
    TestSoftDeletedResurrect) — replace, not merge."""

    def test_cme_resurrect_replaces_ports(self, db):
        from app.core.scan_helpers import cme_upsert_host
        from app.core.utils import new_id, ts_now
        from app.models import Host, Project

        pid = new_id("p")
        db.add(Project(id=pid, name="cme-res", status="active", added=ts_now()))
        db.commit()
        h = Host(id=new_id("hst"), pid=pid, ip="10.0.1.9", hostname="", os="",
                 status="up", ports=["445/tcp"], services=[], tags=[],
                 deleted_at="2026-10-22T00:00:00Z")
        db.add(h)
        db.commit()

        obj, created = cme_upsert_host(db, pid, {
            "ip": "10.0.1.9", "hostname": "dc01", "os": "Windows",
            "ports": ["139/tcp"], "services": ["netbios-ssn"],
        })
        assert created is True
        assert obj.deleted_at is None
        assert obj.ports == ["139/tcp"]  # старые 445 не воскресли
