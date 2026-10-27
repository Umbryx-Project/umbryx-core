"""Admin user deletion without project memberships (security test 2026-09-02, finding 6).

DELETE /api/admin/users/{uid} returned 500 when the user had no project
memberships left but still owned rows in tables whose FK to users.id had no
ON DELETE action (notifications — RESTRICTed in PG; audit_log.actor_id and
pb_automations.owner_id likewise). Root cause fixed in the models + alembic
080; these tests pin the behavior.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.utils import new_id, ts_now

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "DelUser1234!ok"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    yield


def _mk_user(module_db: Session, name: str):
    from app import models
    from app.core.utils import new_id, ts_now

    uid = new_id("u")
    module_db.add(
        models.User(
            id=uid, username=name, display_name=name, password_hash="x",
            role="user", created_at=ts_now(), active=True,
        )
    )
    module_db.commit()
    return uid


class TestAdminDeleteUser:
    def test_delete_user_with_no_memberships(self, module_client: TestClient, module_db: Session):
        uid = _mk_user(module_db, "del_nomember")
        r = module_client.delete(f"/api/admin/users/{uid}")
        assert r.status_code == 204, r.text

    def test_delete_user_with_surviving_notifications(self, module_client: TestClient, module_db: Session):
        """The exact stand scenario: projects gone (memberships cascaded
        away), but the user's notifications survive — deletion must still be
        204 and cascade the notifications away."""
        from app import models

        uid = _mk_user(module_db, "del_with_notif")
        module_db.add(
            models.Notification(
                id=new_id("ntf"),
                user_id=uid, type="info", title="stale", project_id="prj_gone",
            )
        )
        module_db.commit()

        r = module_client.delete(f"/api/admin/users/{uid}")
        assert r.status_code == 204, r.text
        assert module_db.query(models.Notification).filter_by(user_id=uid).count() == 0

    def test_delete_user_with_audit_trail_keeps_audit_anonymized(
        self, module_client: TestClient, module_db: Session
    ):
        """Audit entries must SURVIVE user deletion (they are forensic
        evidence) with actor_id set to NULL, not deleted."""
        from app import models
        from app.core.utils import new_id

        uid = _mk_user(module_db, "del_with_audit")
        entry_id = new_id("aud")
        module_db.add(
            models.AuditEntry(
                id=entry_id,
                ts=__import__("datetime").datetime.now(__import__("datetime").UTC),
                action="test.action",
                actor_id=uid,
                actor_name="del_with_audit",
                target_type="user",
                target_id="x",
            )
        )
        module_db.commit()

        r = module_client.delete(f"/api/admin/users/{uid}")
        assert r.status_code == 204, r.text
        entry = module_db.query(models.AuditEntry).filter_by(id=entry_id).first()
        assert entry is not None  # audit trail preserved
        assert entry.actor_id is None  # anonymized, not orphaned

    def test_delete_user_with_active_membership(self, module_client: TestClient, module_db: Session):
        """The штатный path keeps working: memberships cascade away."""
        from app import models

        uid = _mk_user(module_db, "del_with_member")
        pid = new_id("prj")
        module_db.add(models.Project(id=pid, name="DelMemberTest", added="2024-01-01"))
        module_db.add(models.ProjectMember(id=new_id("pm"), project_id=pid, user_id=uid, role="operator", is_active=True, created_at=ts_now(), source="direct"))
        module_db.commit()

        r = module_client.delete(f"/api/admin/users/{uid}")
        assert r.status_code == 204, r.text
        assert module_db.query(models.ProjectMember).filter_by(user_id=uid).count() == 0

    def test_cannot_delete_self(self, module_client: TestClient):
        # find admin uid via /api/auth/me
        me = module_client.get("/api/auth/me").json()
        r = module_client.delete(f"/api/admin/users/{me['id']}")
        assert r.status_code == 400

    def test_delete_user_preserves_timeline_and_authorship(
        self, module_client: TestClient, module_db: Session
    ):
        """Timeline events carry the author as a plain username string with
        NO FK to users — deleting a user must never touch them and the
        'who did it' attribution must stay readable."""
        from app import models
        from app.core.utils import new_id, ts_now

        uid = _mk_user(module_db, "del_with_timeline")
        pid = new_id("prj")
        module_db.add(models.Project(id=pid, name="DelTlTest", added="2024-01-01"))
        ev_id = new_id("tl")
        module_db.add(
            models.TimelineEvent(
                id=ev_id, pid=pid, username="del_with_timeline",
                entity="note", action="create", label="DelTlTest note",
                meta={}, ts=ts_now(),
            )
        )
        module_db.commit()

        r = module_client.delete(f"/api/admin/users/{uid}")
        assert r.status_code == 204, r.text
        ev = module_db.query(models.TimelineEvent).filter_by(id=ev_id).first()
        assert ev is not None  # the event itself survived
        assert ev.username == "del_with_timeline"  # authorship preserved
