"""
Phase 8 — Platform Maturity: Organization Plans, Marketplace, Plan enforcement.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    r = c.post("/api/orgs", json={"name": "Plan Test Org", "slug": "plan-test"})
    assert r.status_code in (200, 201, 409)
    _s["org_id"] = r.json()["id"]

    yield
    c.post("/api/auth/logout")


class TestOrganizationPlans:
    def test_get_org_plan_default_free(self, module_client: TestClient):
        r = module_client.get(f"/api/marketplace/plans/{_s['org_id']}")
        assert r.status_code == 200
        data = r.json()
        assert data["tier"] == "free"
        assert data["max_members"] == 5
        # Free is Community Edition: no deployment at all, so neither infra
        # stacks nor provisioned workstations get an allowance. The operator's
        # own machines (attacker-SSH, manually registered pool machines) are
        # not metered by these limits. See docs/modules/EDITIONS.md.
        assert data["max_infra_instances"] == 0
        assert data["max_workstations"] == 0

    def test_update_plan_to_team(self, module_client: TestClient):
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "team"})
        assert r.status_code == 200
        data = r.json()
        assert data["tier"] == "team"
        assert data["max_members"] == 10
        assert "infra_lifecycle" in data["features"]
        assert "workstations" in data["features"]

    def test_update_plan_to_pro(self, module_client: TestClient):
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "pro"})
        assert r.status_code == 200
        data = r.json()
        assert data["tier"] == "pro"
        assert data["max_members"] == -1
        assert "cloud_provider_tier1" in data["features"]
        assert "dns_management" in data["features"]

    def test_update_plan_to_enterprise(self, module_client: TestClient):
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "enterprise"})
        assert r.status_code == 200
        data = r.json()
        assert data["tier"] == "enterprise"
        assert "sso" in data["features"]
        assert "priority_support" in data["features"]

    def test_update_plan_to_free(self, module_client: TestClient):
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "free"})
        assert r.status_code == 200
        assert r.json()["tier"] == "free"
        assert r.json()["features"] == []

    def test_update_unknown_tier_400(self, module_client: TestClient):
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "unknown"})
        assert r.status_code == 400


@pytest.mark.ee
class TestMarketplaceTemplates:
    def test_marketplace_templates(self, module_client: TestClient):
        module_client.get("/api/infra-v2/templates")  # triggers builtin-template seeding
        r = module_client.get("/api/marketplace/templates")
        assert r.status_code == 200
        data = r.json()
        assert "builtin" in data
        assert "community" in data
        assert len(data["builtin"]) >= 6

    def test_marketplace_plans_list(self, module_client: TestClient):
        r = module_client.get("/api/marketplace/plans")
        assert r.status_code == 200
        data = r.json()
        assert "free" in data
        assert "team" in data
        assert "pro" in data
        assert "enterprise" in data
        assert data["free"]["max_members"] == 5
        assert data["enterprise"]["max_members"] == -1


class TestPlanUnit:
    def test_tier_limits_structure(self):
        from app.core.plan import TIER_LIMITS
        assert len(TIER_LIMITS) == 4
        for tier, limits in TIER_LIMITS.items():
            assert "max_members" in limits
            assert "max_infra_instances" in limits
            assert "max_workstations" in limits
            assert "features" in limits

    def test_plan_feature_enum(self):
        from app.core.plan import PlanFeature
        assert PlanFeature.INFRA_LIFECYCLE == "infra_lifecycle"
        assert PlanFeature.WORKSTATIONS == "workstations"
        assert PlanFeature.SSO == "sso"

    def test_has_feature(self, module_db):
        from app.core.plan import PlanFeature, has_feature
        result = has_feature(_s["org_id"], PlanFeature.SSO, module_db)
        assert result is False

    def test_check_member_limit(self, module_db):
        from app.core.plan import check_member_limit
        assert check_member_limit(_s["org_id"], module_db) is True

    def test_check_org_limit_bypassed_in_tests(self, module_db):
        # require_plan_feature was removed as dead code (ФТ-14); the live
        # enforcement path is check_org_limit, which is bypassed under
        # APP_ENV=test so the shared in-memory DB doesn't trip the gate.
        from app.core.plan import check_org_limit
        assert check_org_limit(module_db) is True

    def test_ensure_org_plan(self, module_db):
        from app.core.plan import ensure_org_plan
        plan = ensure_org_plan(_s["org_id"], module_db)
        assert plan.tier in ("free", "team", "pro", "enterprise")
