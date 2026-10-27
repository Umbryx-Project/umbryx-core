"""
ФТ-3 (docs/modules/LICENSING_TZ.md): per-tier audit trail retention.
"""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import models
from app.core.audit import log_action
from app.core.audit_retention import run_retention_pass

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


def _seed_entry(db, org_id: str, days_old: int) -> str:
    entry = log_action(
        db,
        action="test.seed",
        actor_id=None,
        actor_name="seed",
        target_type="test",
        target_id="x",
        org_id=org_id,
    )
    entry.ts = datetime.now(UTC) - timedelta(days=days_old)
    db.commit()
    return entry.id


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    yield
    c.post("/api/auth/logout")


class TestFreeOrgDefaultRetention:
    def test_entry_within_90_days_survives(self, module_client, module_db):
        # Free tier retention is 90 days since 2026-10-09 (was 30).
        r = module_client.post("/api/orgs", json={"name": "Retention Free", "slug": "retention-free"})
        org_id = r.json()["id"]
        recent_id = _seed_entry(module_db, org_id, days_old=10)
        old_id = _seed_entry(module_db, org_id, days_old=120)

        run_retention_pass(module_db)

        remaining_ids = {
            e.id for e in module_db.query(models.AuditEntry).filter_by(org_id=org_id).all()
        }
        assert recent_id in remaining_ids
        assert old_id not in remaining_ids


class TestTierRetentionWindows:
    def test_team_org_keeps_90_day_entry(self, module_client, module_db):
        r = module_client.post("/api/orgs", json={"name": "Retention Team", "slug": "retention-team"})
        org_id = r.json()["id"]
        module_client.patch(f"/api/marketplace/plans/{org_id}", json={"tier": "team"})
        kept_id = _seed_entry(module_db, org_id, days_old=60)  # would be purged on Free before it was 90d
        purged_id = _seed_entry(module_db, org_id, days_old=100)  # beyond Team's 90d

        run_retention_pass(module_db)

        remaining_ids = {
            e.id for e in module_db.query(models.AuditEntry).filter_by(org_id=org_id).all()
        }
        assert kept_id in remaining_ids
        assert purged_id not in remaining_ids

    def test_enterprise_org_never_auto_purged(self, module_client, module_db):
        r = module_client.post(
            "/api/orgs", json={"name": "Retention Enterprise", "slug": "retention-enterprise"}
        )
        org_id = r.json()["id"]
        module_client.patch(f"/api/marketplace/plans/{org_id}", json={"tier": "enterprise"})
        ancient_id = _seed_entry(module_db, org_id, days_old=3650)

        run_retention_pass(module_db)

        remaining_ids = {
            e.id for e in module_db.query(models.AuditEntry).filter_by(org_id=org_id).all()
        }
        assert ancient_id in remaining_ids


class TestUnattributedEntriesUntouched:
    def test_null_org_id_entry_survives(self, module_db):
        entry = log_action(
            module_db, action="test.unattributed", actor_id=None, actor_name="seed"
        )
        entry.ts = datetime.now(UTC) - timedelta(days=9999)
        module_db.commit()

        run_retention_pass(module_db)

        assert module_db.query(models.AuditEntry).filter_by(id=entry.id).first() is not None


class TestRetentionFloorPreventsDataLossOnLapse:
    """A lapsed/downgraded license drops the org plan to Free (30d), but
    history written under a longer licensed retention must survive."""

    @pytest.fixture(autouse=True)
    def _clean_state(self, module_db):
        from tests._license_test_utils import reset_instance_license

        reset_instance_license(module_db)
        yield
        reset_instance_license(module_db)

    def _set_floor(self, db, days):
        from app.core.license import get_instance_license_state

        state = get_instance_license_state(db)
        state.retention_floor_days = days
        db.commit()

    def test_floor_keeps_entries_beyond_current_plan_window(self, module_client, module_db):
        r = module_client.post("/api/orgs", json={"name": "Floor 365", "slug": "retention-floor-365"})
        org_id = r.json()["id"]
        self._set_floor(module_db, 365)
        kept_id = _seed_entry(module_db, org_id, days_old=200)
        purged_id = _seed_entry(module_db, org_id, days_old=400)

        run_retention_pass(module_db)

        remaining_ids = {
            e.id for e in module_db.query(models.AuditEntry).filter_by(org_id=org_id).all()
        }
        assert kept_id in remaining_ids
        assert purged_id not in remaining_ids

    def test_unlimited_floor_disables_purge(self, module_client, module_db):
        r = module_client.post("/api/orgs", json={"name": "Floor Unl", "slug": "retention-floor-unl"})
        org_id = r.json()["id"]
        self._set_floor(module_db, -1)
        ancient_id = _seed_entry(module_db, org_id, days_old=3650)

        run_retention_pass(module_db)

        assert module_db.query(models.AuditEntry).filter_by(id=ancient_id).first() is not None


class TestRaiseRetentionFloor:
    @pytest.mark.parametrize(
        ("current", "granted", "expected"),
        [
            (None, 90, 90),
            (365, 30, 365),
            (90, 365, 365),
            (365, -1, -1),
            (-1, 30, -1),
            (90, None, 90),
        ],
    )
    def test_floor_only_grows(self, current, granted, expected):
        from app.core.license import _raise_retention_floor

        assert _raise_retention_floor(current, granted) == expected


class TestApiNoLongerReturnsPurgedEntries:
    def test_purged_entry_absent_from_audit_log_api(self, module_client, module_db):
        r = module_client.post("/api/orgs", json={"name": "Retention API", "slug": "retention-api"})
        org_id = r.json()["id"]
        purged_id = _seed_entry(module_db, org_id, days_old=120)

        run_retention_pass(module_db)

        r = module_client.get("/api/audit/log", params={"limit": 1000})
        ids = {e["id"] for e in r.json()["items"]}
        assert purged_id not in ids
