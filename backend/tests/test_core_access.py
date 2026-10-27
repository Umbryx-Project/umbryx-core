"""Tests for app.core.access — permission checks and evaluation."""
from unittest.mock import MagicMock, patch

from app.core.access import (
    _evaluate,
    _resolve_role,
    check_pid_access,
    check_object_access,
    get_user_member_pids,
    user_has_permission,
)
from app.core.errors import AppError


class TestEvaluate:
    def test_admin_grants_access(self):
        user = MagicMock()
        with patch("app.core.access.is_admin", return_value=True):
            membership, err = _evaluate(MagicMock(), "p1", user, None)
            assert err is None
            assert membership is None

    def test_not_member_returns_not_member(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=(None, "none")):
            membership, err = _evaluate(db, "p1", user, "hosts.read")
            assert err == "not_member"

    def test_member_with_permission_grants(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "operator"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("operator", "project_member")), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value={"hosts.read"}):
            m, err = _evaluate(db, "p1", user, "hosts.read")
            assert err is None
            assert m == membership

    def test_member_without_permission(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "viewer"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("viewer", "project_member")), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value={"hosts.read"}):
            m, err = _evaluate(db, "p1", user, "hosts.delete")
            assert err == "no_permission"

    def test_no_permission_required(self):
        user = MagicMock()
        membership = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("owner", "project_member")), \
             patch("app.core.access.get_membership", return_value=membership):
            m, err = _evaluate(db, "p1", user, None)
            assert err is None


class TestCheckPidAccess:
    def test_raises_404_not_member(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=(None, "none")):
            try:
                check_pid_access(db, "p1", user, "hosts.read")
                assert False, "Should have raised"
            except AppError as e:
                assert e.status_code == 404

    def test_raises_403_no_permission(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "viewer"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("viewer", "project_member")), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value=set()):
            try:
                check_pid_access(db, "p1", user, "hosts.delete")
                assert False, "Should have raised"
            except AppError as e:
                assert e.status_code == 403

    def test_returns_membership_on_success(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "operator"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("operator", "project_member")), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value={"hosts.read"}):
            result = check_pid_access(db, "p1", user, "hosts.read")
            assert result == membership


class TestAdminBypassAudit:
    """Regression: an admin GET on a project-scoped list with a pid that
    doesn't exist at all used to 500. timeline_events.pid carries a real
    Postgres FK to projects.id (not reflected in the SQLAlchemy model, and
    not enforced by SQLite -- which is why this never reproduced under
    pytest against the test DB) -- _audit_admin_bypass's log_event() write
    for a nonexistent project failed with a ForeignKeyViolation, and the
    except handler's own `user.id` access after that failed flush raised a
    *second*, unhandled PendingRollbackError before db.rollback() could run
    (live Postgres retest, 2026-09-03)."""

    def test_admin_bypass_not_audited_for_nonexistent_project(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=True), \
             patch("app.core.access.get_membership", return_value=None), \
             patch("app.core.access._get_project", return_value=None), \
             patch("app.core.access._audit_admin_bypass") as mock_audit:
            check_pid_access(db, "p_does_not_exist", user, "hosts.read")
            mock_audit.assert_not_called()

    def test_admin_bypass_audited_for_existing_project(self):
        user = MagicMock()
        db = MagicMock()
        project = MagicMock()
        with patch("app.core.access.is_admin", return_value=True), \
             patch("app.core.access.get_membership", return_value=None), \
             patch("app.core.access._get_project", return_value=project), \
             patch("app.core.access._audit_admin_bypass") as mock_audit:
            check_pid_access(db, "p_real", user, "hosts.read")
            mock_audit.assert_called_once()

    def test_audit_write_failure_does_not_raise(self):
        # Defense in depth: even if the audit-log write fails for some
        # other reason (this used to be the FK violation above; could be
        # anything), _audit_admin_bypass must never let that exception
        # escape -- it's explicitly a best-effort side channel.
        from app.core.access import _audit_admin_bypass

        user = MagicMock()
        user.id = "u1"
        user.username = "admin"
        db = MagicMock()
        db.commit.side_effect = Exception("boom")
        with patch("app.core.events.log_event"):
            _audit_admin_bypass(db, "p1", user, "hosts.read")  # must not raise
        db.rollback.assert_called_once()


class TestCheckObjectAccess:
    def test_raises_404_no_pid(self):
        user = MagicMock()
        db = MagicMock()
        try:
            check_object_access(db, None, user, "hosts.read")
            assert False
        except AppError as e:
            assert e.status_code == 404

    def test_delegates_to_check_pid(self):
        user = MagicMock()
        membership = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("operator", "project_member")), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value={"hosts.read"}):
            result = check_object_access(db, "p1", user, "hosts.read")
            assert result == membership


class TestUserHasPermission:
    def test_returns_true(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=("operator", "project_member")), \
             patch("app.core.access.get_membership", return_value=MagicMock()), \
             patch("app.core.access.get_permissions_for_role", return_value={"hosts.read"}):
            assert user_has_permission(db, "p1", user, "hosts.read") is True

    def test_returns_false(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access._resolve_role", return_value=(None, "none")):
            assert user_has_permission(db, "p1", user, "hosts.read") is False


class TestGetUserMemberPids:
    def test_returns_project_ids(self):
        user = MagicMock()
        user.id = "u1"
        m1 = MagicMock()
        m1.project_id = "p1"
        m2 = MagicMock()
        m2.project_id = "p2"
        db = MagicMock()

        def mock_query(model):
            q = MagicMock()
            if model.__name__ in ("OrganizationMember", "TeamMember"):
                q.filter.return_value.all.return_value = []
            else:
                q.filter.return_value.all.return_value = [m1, m2]
            return q

        db.query.side_effect = mock_query
        with patch("app.core.access.is_admin", return_value=False):
            result = get_user_member_pids(db, user)
            assert sorted(result) == ["p1", "p2"]
