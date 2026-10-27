"""
Phase 0.1 — Unit tests for access.py (_evaluate, check_pid_access).

Tests the access control decision logic:
- Admin bypass
- Membership check
- Permission enforcement
"""
import pytest
from unittest.mock import MagicMock

from app.core.access import _evaluate, user_has_permission
from app.core.enums import MemberRole


def _make_user(role="user"):
    u = MagicMock()
    u.role = role
    u.id = "u_test"
    return u


def _make_membership(role="viewer"):
    m = MagicMock()
    m.role = role
    m.is_active = True
    return m


class TestEvaluateAdminBypass:
    def test_admin_gets_access_without_membership(self, db):
        user = _make_user(role="platform_admin")
        mem, err = _evaluate(db, "p_any", user, "hosts.read")
        assert err is None
        assert mem is None

    def test_admin_bypass_ignores_permission_check(self, db):
        user = _make_user(role="platform_admin")
        _, err = _evaluate(db, "p_any", user, "nonexistent.permission")
        assert err is None


class TestEvaluateMembership:
    def test_no_membership_returns_not_member(self, db):
        user = _make_user()
        mem, err = _evaluate(db, "p_nonexistent", user, "hosts.read")
        assert err == "not_member"

    def test_no_permission_returns_no_permission(self, db):
        user = _make_user()
        membership = _make_membership(role="viewer")
        mock_db = MagicMock()
        from app.core.access import get_membership
        original = get_membership
        import app.core.access as _access_mod
        _access_mod.get_membership = lambda db, pid, uid: membership
        try:
            _, err = _evaluate(mock_db, "p_test", user, "hosts.create")
            assert err == "no_permission"
        finally:
            _access_mod.get_membership = original

    def test_valid_membership_with_permission_passes(self, db):
        user = _make_user()
        membership = _make_membership(role="viewer")
        import app.core.access as _access_mod
        original = _access_mod.get_membership
        _access_mod.get_membership = lambda d, pid, uid: membership
        try:
            mem, err = _evaluate(db, "p_test", user, "hosts.read")
            assert err is None
            assert mem is membership
        finally:
            _access_mod.get_membership = original


class TestUserHasPermission:
    def _make_user_with_membership(self, db, role):
        from app.models.auth import User
        from app.models.project import ProjectMember
        from app.core.utils import new_id, ts_now
        uid = new_id("u")
        user = User(id=uid, username=f"test_{role}_{uid[:6]}", display_name="", password_hash="x", role="user", created_at=ts_now(), active=True)
        db.add(user)
        db.flush()
        return user

    def test_viewer_cannot_create(self, db):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("viewer")
        assert "hosts.create" not in perms

    def test_operator_can_create_hosts(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("operator")
        assert "hosts.create" in perms

    def test_analyst_can_create_findings(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("analyst")
        assert "findings.create" in perms

    def test_analyst_cannot_run_scans(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("analyst")
        assert "scans.run" not in perms

    def test_reviewer_can_approve_findings(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("reviewer")
        assert "findings.approve" in perms

    def test_reviewer_cannot_read_hosts(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("reviewer")
        assert "hosts.read" not in perms

    def test_auditor_can_read_audit(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("auditor")
        assert "audit.read" in perms

    def test_auditor_cannot_read_creds(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("auditor")
        assert "credentials.read" not in perms

    def test_unknown_role_returns_empty(self):
        from app.core.permissions import get_permissions_for_role
        perms = get_permissions_for_role("nonexistent")
        assert len(perms) == 0
