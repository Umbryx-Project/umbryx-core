"""
Tests for scan diffing, host risk score, and C2 health features.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone


def _make_db_mock(findings=None, cred_ids=None, creds_host_link=None, path_count=0, cred_counts=None):
    """Build a MagicMock that simulates the db.query chains used by compute_host_risk."""
    db = MagicMock()

    findings = findings or []
    cred_ids = cred_ids or []
    creds_host_link = creds_host_link or []
    cred_counts = cred_counts or {}

    # Query 1: db.query(Finding.severity, Finding.status).filter(...).all() → findings
    q1 = MagicMock()
    q1.filter.return_value.all.return_value = findings

    # Query 2: db.query(CredHostNote.cred_id).filter(...).distinct().all() → cred_ids
    q2 = MagicMock()
    q2.filter.return_value.distinct.return_value.all.return_value = cred_ids

    # Query 3: db.query(Cred.id, Cred.host_ids).filter(...).all() → creds_host_link
    q3 = MagicMock()
    q3.filter.return_value.all.return_value = creds_host_link

    # Query 4: db.query(AttackPathNode).filter(...).count() → path_count
    q4 = MagicMock()
    q4.filter.return_value.count.return_value = path_count

    # For cred reuse: db.query(CredHostNote).filter(...).count() and db.query(Cred).filter(...).first()
    # These are called per-cred if all_cred_ids is non-empty
    # We use side_effect to handle both the initial 4 queries and any subsequent ones

    call_list = [q1, q2, q3, q4]

    def query_side_effect(*args, **kwargs):
        if call_list:
            return call_list.pop(0)
        # Subsequent queries: cred reuse counting
        mock_q = MagicMock()
        mock_q.filter.return_value.count.return_value = 0
        mock_q.filter.return_value.first.return_value = None
        return mock_q

    db.query.side_effect = query_side_effect
    return db


# ── Scan diff engine tests ──────────────────────────────────────────────

class TestScanDiff:
    def test_diff_added_ports(self):
        from app.core.scan_diff import diff_snapshots
        old = {"ports": ["80/tcp", "443/tcp"], "services": ["http"]}
        new = {"ports": ["80/tcp", "443/tcp", "22/tcp"], "services": ["http"]}
        d = diff_snapshots(old, new)
        assert d["added_ports"] == ["22/tcp"]
        assert d["removed_ports"] == []
        assert d["has_changes"] is True

    def test_diff_removed_ports(self):
        from app.core.scan_diff import diff_snapshots
        old = {"ports": ["80/tcp", "443/tcp", "22/tcp"], "services": []}
        new = {"ports": ["80/tcp"], "services": []}
        d = diff_snapshots(old, new)
        assert d["removed_ports"] == ["22/tcp", "443/tcp"]
        assert d["added_ports"] == []
        assert d["has_changes"] is True

    def test_diff_no_changes(self):
        from app.core.scan_diff import diff_snapshots
        snap = {"ports": ["80/tcp"], "services": ["http"], "os": "Linux",
                "hostname": "web1", "domain": "", "findings": []}
        d = diff_snapshots(snap, snap)
        assert d["has_changes"] is False

    def test_diff_os_changed(self):
        from app.core.scan_diff import diff_snapshots
        old = {"os": "Linux", "ports": [], "services": [], "findings": []}
        new = {"os": "Windows", "ports": [], "services": [], "findings": []}
        d = diff_snapshots(old, new)
        assert d["os_changed"] is True
        assert d["os_old"] == "Linux"
        assert d["os_new"] == "Windows"

    def test_diff_new_findings(self):
        from app.core.scan_diff import diff_snapshots
        old = {"findings": [], "ports": [], "services": []}
        new = {"findings": [{"title": "CVE-2024-1234", "severity": "critical", "cve": "CVE-2024-1234"}], "ports": [], "services": []}
        d = diff_snapshots(old, new)
        assert len(d["new_findings"]) == 1
        assert d["new_findings"][0]["title"] == "CVE-2024-1234"
        assert d["has_changes"] is True

    def test_diff_resolved_findings(self):
        from app.core.scan_diff import diff_snapshots
        old = {"findings": [{"title": "SQLi", "severity": "high", "cve": ""}], "ports": [], "services": []}
        new = {"findings": [], "ports": [], "services": []}
        d = diff_snapshots(old, new)
        assert len(d["resolved_findings"]) == 1
        assert d["resolved_findings"][0]["title"] == "SQLi"

    def test_diff_services_changed(self):
        from app.core.scan_diff import diff_snapshots
        old = {"ports": [], "services": ["http", "ssh"]}
        new = {"ports": [], "services": ["http", "rdp"]}
        d = diff_snapshots(old, new)
        assert d["added_services"] == ["rdp"]
        assert d["removed_services"] == ["ssh"]


# ── Risk score tests ────────────────────────────────────────────────────

def _mock_host(**kwargs):
    h = MagicMock()
    h.id = kwargs.get("id", "h1")
    h.pid = kwargs.get("pid", "p1")
    h.status = kwargs.get("status", "unknown")
    h.role = kwargs.get("role", "unknown")
    h.ip = kwargs.get("ip", "10.0.0.1")
    h.hostname = kwargs.get("hostname", "")
    h.ports = kwargs.get("ports", [])
    h.services = kwargs.get("services", [])
    h.tags = kwargs.get("tags", [])
    h.domain = kwargs.get("domain", "")
    h.deleted_at = None
    return h


class TestRiskScore:
    def test_unknown_host_low_score(self):
        from app.core.risk_score import compute_host_risk
        db = _make_db_mock()
        host = _mock_host(status="unknown", role="unknown")
        result = compute_host_risk(db, host)
        assert result["score"] == 0
        assert result["level"] == "info"

    def test_pwned_host_high_score(self):
        from app.core.risk_score import compute_host_risk
        db = _make_db_mock()
        host = _mock_host(status="pwned", role="unknown")
        result = compute_host_risk(db, host)
        assert result["score"] >= 28
        assert result["level"] in ("low", "medium", "high", "critical")

    def test_dc_role_bonus(self):
        from app.core.risk_score import compute_host_risk
        db = _make_db_mock()
        host = _mock_host(status="unknown", role="dc")
        result = compute_host_risk(db, host)
        assert result["breakdown"]["role"] == 15
        assert result["score"] >= 15

    def test_owned_host_max_status_score(self):
        from app.core.risk_score import compute_host_risk
        db = _make_db_mock()
        host = _mock_host(status="owned", role="dc")
        result = compute_host_risk(db, host)
        assert result["score"] >= 45

    def test_findings_contribute(self):
        from app.core.risk_score import compute_host_risk
        db = _make_db_mock(findings=[("critical", "open"), ("critical", "open"), ("high", "open")])
        host = _mock_host(status="access", role="server")
        result = compute_host_risk(db, host)
        assert result["breakdown"]["findings"] > 0
        assert result["breakdown"]["open_findings"] == 3

    def test_score_capped_at_100(self):
        from app.core.risk_score import compute_host_risk
        findings = [("critical", "open")] * 20
        db = _make_db_mock(findings=findings, path_count=10)
        host = _mock_host(status="owned", role="dc")
        result = compute_host_risk(db, host)
        assert result["score"] <= 100

    def test_resolved_findings_dont_count(self):
        from app.core.risk_score import compute_host_risk
        db = _make_db_mock(findings=[("critical", "resolved"), ("high", "false_positive")])
        host = _mock_host(status="scanned", role="unknown")
        result = compute_host_risk(db, host)
        assert result["breakdown"]["open_findings"] == 0
        assert result["breakdown"]["findings"] == 0


# ── C2 health tests ─────────────────────────────────────────────────────

class TestC2Health:
    def test_stale_detection_alive_recent(self):
        from app.routers.c2._sessions import _is_session_stale
        agent = {"alive": True, "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        cfg = {"type": "adaptix"}
        assert _is_session_stale(agent, cfg) is False

    def test_stale_detection_dead(self):
        from app.routers.c2._sessions import _is_session_stale
        agent = {"alive": False, "last_seen": ""}
        cfg = {"type": "adaptix"}
        assert _is_session_stale(agent, cfg) is True

    def test_stale_detection_old_checkin(self):
        from app.routers.c2._sessions import _is_session_stale
        from datetime import timedelta
        old_time = datetime.now(timezone.utc) - timedelta(minutes=60)
        agent = {"alive": True, "last_seen": old_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        cfg = {"type": "adaptix"}
        assert _is_session_stale(agent, cfg) is True

    def test_stale_detection_no_last_seen(self):
        from app.routers.c2._sessions import _is_session_stale
        agent = {"alive": True, "last_seen": ""}
        cfg = {"type": "adaptix"}
        assert _is_session_stale(agent, cfg) is False
