"""Community Edition semantics on an unlicensed instance.

CE deploys nothing. These tests lock in the three properties that make
that true and keep it true (docs/modules/EDITIONS.md):

1. Deployment is blocked with 402 on an unlicensed instance — the infra
   lifecycle router as a whole, and every workstation provisioning entry
   point.
2. What CE keeps is open: reading and tearing down what already exists,
   and the operator's own machines — registering an existing machine over
   SSH into the pool, binding it, granting and revoking access. Those are
   never gated, because the action log and audit trail hang off them.
3. The gate reads the *signed license*, not `OrganizationPlan.tier`.
   A self-hosted customer owns their Postgres and can set that row to
   'enterprise' at will (MONETIZATION.md calls this out as the critical
   hole), so the deployment gate must not be satisfiable that way.
"""
import pytest
from fastapi.testclient import TestClient

from app.core.editions import ee_available

from ._license_test_utils import license_ee, license_instance, reset_instance_license

# The infra-v2 routes only exist in an Enterprise build. There they answer
# 402 when the instance is unlicensed, which is what these tests assert; in
# a Community tree the routers are never mounted and the honest answer is
# 404 — a different fact, covered by test_editions_seam.py. Marked rather
# than loosened to "402 or 404", so each edition's answer stays pinned.
needs_ee_build = pytest.mark.skipif(
    not ee_available(), reason="infra-v2 routes are not mounted in a Community build"
)

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}

DEPLOY_BODY = {
    "blueprint_id": "bp-test",
    "name": "gate-probe",
    "services": [{"name": "svc", "role": "redirector"}],
    "env_vars": {},
}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    reset_instance_license(module_db)
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    assert c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS}).status_code == 200

    r = c.post("/api/orgs", json={"name": "Edition Org", "slug": "edition-ce"})
    assert r.status_code in (200, 201), r.text
    _s["org_id"] = r.json()["id"]

    r = c.post(
        "/api/projects",
        json={"name": "Edition Project", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (200, 201), r.text
    _s["pid"] = r.json()["id"]
    assert c.patch(f"/api/projects/{_s['pid']}", json={"org_id": _s["org_id"]}).status_code == 200

    yield
    reset_instance_license(module_db)
    c.post("/api/auth/logout")


class TestDeploymentBlocked:
    @needs_ee_build
    def test_infra_stack_deploy_is_payment_required(self, module_client: TestClient):
        r = module_client.post("/api/infra-v2/stacks/deploy", json=DEPLOY_BODY)
        assert r.status_code == 402, r.text
        assert "Community Edition" in r.json()["detail"]

    @needs_ee_build
    def test_infra_provider_create_is_payment_required(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/providers", json={"name": "p", "type": "docker", "config": {}}
        )
        assert r.status_code == 402, r.text

    def test_workstation_create_is_payment_required(self, module_client: TestClient):
        r = module_client.post(
            "/api/workstations",
            json={"project_id": _s["pid"], "template_id": "tpl-x", "name": "ws-gate"},
        )
        assert r.status_code == 402, r.text

    def test_workstation_provision_is_payment_required(self, module_client: TestClient):
        r = module_client.post("/api/workstations/ws-nonexistent/provision")
        assert r.status_code == 402, r.text

    def test_pool_provisioning_is_payment_required(self, module_client: TestClient):
        r = module_client.post(
            "/api/workstations/pool", json={"infra_provider_id": "prov-x", "name": "pool-gate"}
        )
        assert r.status_code == 402, r.text

    def test_workstation_template_create_is_payment_required(self, module_client: TestClient):
        r = module_client.post("/api/workstations/templates", json={"name": "tpl-gate"})
        assert r.status_code == 402, r.text


class TestReadAndTeardownStayOpen:
    """The license gate's standing rule: a customer can always look at and
    wind down what they already have. The edition gate follows it."""

    @needs_ee_build
    def test_stack_list_readable(self, module_client: TestClient):
        assert module_client.get("/api/infra-v2/stacks").status_code == 200

    @needs_ee_build
    def test_provider_list_readable(self, module_client: TestClient):
        assert module_client.get("/api/infra-v2/providers").status_code == 200

    @needs_ee_build
    def test_stack_delete_not_gated(self, module_client: TestClient):
        # 404 for a stack that does not exist — the point is that it is not 402.
        r = module_client.delete("/api/infra-v2/stacks/stk-nonexistent")
        assert r.status_code != 402, r.text

    def test_workstation_destroy_not_gated(self, module_client: TestClient):
        r = module_client.post("/api/workstations/ws-nonexistent/destroy")
        assert r.status_code != 402, r.text


class TestOwnMachinesStayOpen:
    """CE keeps the operator's own machines: attacker-SSH is not gated by
    any PlanFeature at all, and the pool's manual-registration and access
    paths must not hit the provisioning gate."""

    def test_register_existing_machine_over_ssh_not_gated(self, module_client: TestClient):
        r = module_client.post(
            "/api/workstations/pool/ignored/register-manual",
            json={
                "name": "my-own-box",
                "access_address": "198.51.100.10",
                "ssh_user": "root",
                "auth": {"type": "password", "secret": "s3cret"},
            },
        )
        assert r.status_code != 402, r.text
        assert r.status_code == 201, r.text
        _s["ws_id"] = r.json()["id"]

    def test_registering_many_machines_is_not_limited(self, module_client: TestClient):
        """max_workstations = 0 on Free must not reach manual registration —
        those are machines the operator already owns, not provisioned ones."""
        for i in range(4):
            r = module_client.post(
                "/api/workstations/pool/ignored/register-manual",
                json={
                    "name": f"own-box-{i}",
                    "access_address": f"198.51.100.2{i}",
                    "auth": {"type": "password", "secret": "s3cret"},
                },
            )
            assert r.status_code == 201, r.text

    def test_pool_listing_and_access_paths_not_gated(self, module_client: TestClient):
        assert module_client.get("/api/workstations/pool").status_code == 200
        ws_id = _s.get("ws_id", "ws-nonexistent")
        for path in (f"/api/workstations/pool/{ws_id}/test", f"/api/workstations/pool/{ws_id}/refresh"):
            assert module_client.post(path).status_code != 402, path

    def test_access_revoke_not_gated(self, module_client: TestClient):
        ws_id = _s.get("ws_id", "ws-nonexistent")
        r = module_client.post(f"/api/workstations/pool/{ws_id}/revoke", json={})
        assert r.status_code != 402, r.text


class TestGateReadsSignedLicenseOnly:
    @needs_ee_build
    def test_editing_the_org_plan_row_does_not_unlock_deployment(self, module_client: TestClient):
        """The whole point of the instance entitlement: a tier written into
        the customer's own database grants nothing."""
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "enterprise"})
        assert r.status_code == 200, r.text
        r = module_client.post("/api/infra-v2/stacks/deploy", json=DEPLOY_BODY)
        assert r.status_code == 402, "an editable DB row must not satisfy the deployment gate"

    @needs_ee_build
    def test_signed_enterprise_license_unlocks_deployment(
        self, module_client: TestClient, module_db, monkeypatch
    ):
        # Probe with a connectivity test rather than a real deploy: the
        # assertion is about the gate, and a deploy that gets past it goes
        # on to fail on a nonexistent blueprint and poison the session.
        probe = {"type": "docker", "config": {}}
        assert module_client.post("/api/infra-v2/providers/test", json=probe).status_code == 402

        license_instance(module_client, module_db, monkeypatch, tier="enterprise")
        r = module_client.post("/api/infra-v2/providers/test", json=probe)
        assert r.status_code != 402, r.text

        reset_instance_license(module_db)
        assert module_client.post("/api/infra-v2/providers/test", json=probe).status_code == 402


class TestExtendedRolesGating:
    """The client-facing review roles are Team+ (MONETIZATION.md), the base
    roles are free on every tier because RBAC is a security feature.

    Gated on the *instance* tier, not on OrganizationPlan: that row is in
    the customer's own database. And on the tier rather than a new
    PlanFeature — a license token carries an explicit feature list, so a
    new flag would silently withdraw the capability from every token
    already issued.
    """

    @pytest.fixture
    def member(self, module_client: TestClient):
        import uuid

        name = f"role_probe_{uuid.uuid4().hex[:8]}"
        r = module_client.post(
            "/api/admin/users", json={"username": name, "password": "RolePass1234!", "role": "user"}
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    @pytest.mark.parametrize("role", ["reviewer", "analyst", "observer"])
    def test_extended_role_refused_unlicensed(self, module_client: TestClient, member, role):
        r = module_client.post(
            f"/api/projects/{_s['pid']}/members", json={"user_id": member, "role": role}
        )
        assert r.status_code == 402, r.text
        assert role in r.json()["detail"]

    @pytest.mark.parametrize("role", ["operator", "viewer", "auditor", "editor", "team_lead"])
    def test_base_roles_allowed_unlicensed(self, module_client: TestClient, member, role):
        """Never gate the base roles: RBAC is how an unlicensed install
        keeps a read-only auditor out of credentials."""
        r = module_client.post(
            f"/api/projects/{_s['pid']}/members", json={"user_id": member, "role": role}
        )
        assert r.status_code == 201, r.text

    def test_extended_role_allowed_once_licensed(
        self, module_client: TestClient, module_db, member, monkeypatch
    ):
        undo = license_ee(module_client, module_db, tier="team")
        try:
            r = module_client.post(
                f"/api/projects/{_s['pid']}/members", json={"user_id": member, "role": "analyst"}
            )
            assert r.status_code == 201, r.text
        finally:
            undo()

    def test_org_member_role_is_gated_too(self, module_client: TestClient, member):
        """Same enum, same rule — the org membership routes must not be a
        way around the project ones."""
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/members", json={"user_id": member, "role": "observer"}
        )
        assert r.status_code == 402, r.text
