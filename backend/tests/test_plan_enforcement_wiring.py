"""
ФТ-1 (docs/modules/LICENSING_TZ.md): wiring the already-existing plan
enforcement primitives (check_member_limit, check_infra_limit,
check_provider_type_allowed, has_feature) into the actual API routes.

Before this change, core/plan.py's enforcement functions existed but were
never called from any router — see docs/modules/MONETIZATION_GAP_AUDIT.md.
This test module locks in that they now actually block over-limit / wrong-
tier requests, and that upgrading the org's plan unblocks them.
"""
import pytest
from fastapi.testclient import TestClient

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "RolePass1234!"
_s: dict = {}


def _pin_infra_limit(db, org_id: str, limit: int) -> None:
    """Pin an org's stack allowance directly on the plan row.

    The downgrade behaviour under test needs a *nonzero* allowance with
    excess above it. No tier provides that any more: Free is Community
    Edition and allows 0 stacks (docs/modules/EDITIONS.md), every paid tier
    is unlimited. Pinning the number states what the test actually depends
    on instead of borrowing a tier's incidental value.
    """
    from app import models

    plan = (
        db.query(models.OrganizationPlan)
        .filter(models.OrganizationPlan.org_id == org_id)
        .first()
    )
    plan.max_infra_instances = limit
    db.commit()


def _create_user(c: TestClient, username: str) -> str:
    r = c.post("/api/admin/users", json={"username": username, "password": USER_PASS, "role": "user"})
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


def _set_tier(c: TestClient, org_id: str, tier: str):
    r = c.patch(f"/api/marketplace/plans/{org_id}", json={"tier": tier})
    assert r.status_code == 200, r.text


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200

    r = c.post("/api/orgs", json={"name": "Plan Enforcement Org", "slug": "plan-enforcement"})
    assert r.status_code in (200, 201), r.text
    _s["org_id"] = r.json()["id"]

    r = c.post(
        "/api/projects",
        json={"name": "Plan Enforcement Project", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (200, 201), r.text
    _s["pid"] = r.json()["id"]
    r = c.patch(f"/api/projects/{_s['pid']}", json={"org_id": _s["org_id"]})
    assert r.status_code == 200, r.text

    yield
    c.post("/api/auth/logout")



@pytest.fixture(scope="class")
def licensed_instance(module_client: TestClient, module_db):
    """A licensed instance for classes that test the *per-org* tier checks.

    Those checks sit underneath the instance-wide deployment gate
    (docs/modules/EDITIONS.md): unlicensed, every infra route answers 402
    and the org-level distinctions become unobservable. Licensing is
    per class, not per module, because this module also holds tests that
    assert what an *unlicensed* instance refuses.

    The license syncs every org to the licensed tier, so the org under
    test is put back on Free afterwards — the state these tests start from.
    """
    undo = license_ee(module_client, module_db)
    _set_tier(module_client, _s["org_id"], "free")
    yield
    undo()


class TestMemberLimit:
    """Free tier: max_members = 5. Org creator already occupies 1 slot."""

    def test_add_up_to_limit_succeeds(self, module_client: TestClient):
        # Free tier: max_members = 5; the org creator occupies 1 slot,
        # so 4 more members fit (2026-10-09: limit raised 3 → 5).
        c = module_client
        for i in range(4):
            uid = _create_user(c, f"plan_member_{i}")
            r = c.post(f"/api/orgs/{_s['org_id']}/members", json={"user_id": uid, "role": "viewer"})
            assert r.status_code == 201, r.text

    def test_add_beyond_limit_rejected(self, module_client: TestClient):
        c = module_client
        for i in range(10, 14):  # fill up to the 5-member cap
            uid = _create_user(c, f"plan_member_fill_{i}")
            c.post(f"/api/orgs/{_s['org_id']}/members", json={"user_id": uid, "role": "viewer"})
        uid = _create_user(c, "plan_member_over_limit")
        r = c.post(f"/api/orgs/{_s['org_id']}/members", json={"user_id": uid, "role": "viewer"})
        assert r.status_code == 402, r.text

    def test_role_change_on_existing_member_not_blocked(self, module_client: TestClient):
        # Updating an existing member's role must not count as "adding" —
        # it should never be blocked by the member limit.
        c = module_client
        # Fill to the cap first, then confirm a further add is blocked…
        for i in range(20, 24):
            _uid = _create_user(c, f"plan_member_rc_{i}")
            c.post(f"/api/orgs/{_s['org_id']}/members", json={"user_id": _uid, "role": "viewer"})
        uid = _create_user(c, "plan_member_role_change_target")
        r = c.post(f"/api/orgs/{_s['org_id']}/members", json={"user_id": uid, "role": "viewer"})
        assert r.status_code == 402

        r = c.get(f"/api/orgs/{_s['org_id']}/members")
        assert r.status_code == 200
        existing_uid = next(m["user_id"] for m in r.json() if m["role"] == "viewer")
        r = c.post(
            f"/api/orgs/{_s['org_id']}/members", json={"user_id": existing_uid, "role": "manager"}
        )
        assert r.status_code == 201, r.text

    def test_create_org_user_beyond_limit_rejected(self, module_client: TestClient):
        c = module_client
        r = c.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={"username": "plan_new_user_over_limit", "password": USER_PASS, "role": "viewer"},
        )
        assert r.status_code == 402, r.text


@pytest.mark.usefixtures("licensed_instance")
@pytest.mark.ee
class TestCloudProviderTierGating:
    def test_free_org_denied_hetzner(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/providers",
            json={"name": "hz-1", "type": "hetzner", "category": "cloud", "org_id": _s["org_id"]},
        )
        assert r.status_code == 402, r.text

    def test_free_org_denied_aws(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/providers",
            json={"name": "aws-1", "type": "aws", "category": "cloud", "org_id": _s["org_id"]},
        )
        assert r.status_code == 402, r.text

    def test_pro_org_allowed_hetzner_still_denied_aws(self, module_client: TestClient):
        c = module_client
        _set_tier(c, _s["org_id"], "pro")
        r = c.post(
            "/api/infra-v2/providers",
            json={"name": "hz-2", "type": "hetzner", "category": "cloud", "org_id": _s["org_id"]},
        )
        assert r.status_code == 201, r.text
        r = c.post(
            "/api/infra-v2/providers",
            json={"name": "aws-2", "type": "aws", "category": "cloud", "org_id": _s["org_id"]},
        )
        assert r.status_code == 402, r.text

    def test_team_org_denied_route53(self, module_client: TestClient):
        # Route53 is Pro+ per MONETIZATION.md (Pro's "DNS — расширенный"),
        # not Enterprise-only — confirm Team alone isn't enough.
        c = module_client
        _set_tier(c, _s["org_id"], "team")
        r = c.post(
            "/api/infra-v2/providers",
            json={"name": "r53-team", "type": "route53", "category": "dns", "org_id": _s["org_id"]},
        )
        assert r.status_code == 402, r.text
        _set_tier(c, _s["org_id"], "pro")

    def test_pro_org_allowed_route53(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/providers",
            json={"name": "r53-1", "type": "route53", "category": "dns", "org_id": _s["org_id"]},
        )
        assert r.status_code == 201, r.text

    def test_enterprise_org_allowed_aws(self, module_client: TestClient):
        c = module_client
        _set_tier(c, _s["org_id"], "enterprise")
        r = c.post(
            "/api/infra-v2/providers",
            json={"name": "aws-3", "type": "aws", "category": "cloud", "org_id": _s["org_id"]},
        )
        assert r.status_code == 201, r.text
        _set_tier(c, _s["org_id"], "free")  # reset for the remaining test classes


@pytest.mark.usefixtures("licensed_instance")
@pytest.mark.ee
class TestVpnGenerationGating:
    @pytest.fixture(scope="class", autouse=True)
    def _docker_provider(self, module_client: TestClient, licensed_instance):
        # docker/ssh_host provider types aren't tier-gated themselves —
        # only VPN generation on top of them is.
        r = module_client.post(
            "/api/infra-v2/providers",
            json={
                "name": "vpn-host",
                "type": "docker",
                "category": "cloud",
                "org_id": _s["org_id"],
                "host": "10.0.0.1",
            },
        )
        assert r.status_code == 201, r.text
        _s["vpn_provider_id"] = r.json()["id"]

    def test_free_org_denied_vpn_setup(self, module_client: TestClient):
        r = module_client.post(f"/api/infra-v2/providers/{_s['vpn_provider_id']}/vpn/setup")
        assert r.status_code == 402, r.text

    def test_free_org_denied_vpn_client(self, module_client: TestClient):
        r = module_client.post(
            f"/api/infra-v2/providers/{_s['vpn_provider_id']}/vpn/clients", json={"name": "op1"}
        )
        assert r.status_code == 402, r.text

    def test_team_org_allowed_past_gate(self, module_client: TestClient, module_db):
        # Upgrading unblocks the gate; the underlying WireGuard SSH call to
        # a fake host is out of scope here (network I/O) — the gate itself
        # is what ФТ-1 is about, checked directly against plan.py to keep
        # this test deterministic.
        from app.core.plan import PlanFeature, has_feature

        _set_tier(module_client, _s["org_id"], "team")
        assert has_feature(_s["org_id"], PlanFeature.VPN_GENERATION, module_db) is True
        _set_tier(module_client, _s["org_id"], "free")


@pytest.mark.ee
class TestInfraInstanceLimit:
    """The limit mechanism itself: the first stack fits, the next does not.

    Pinned to a limit of 1 on the plan row rather than relying on whatever
    Free happens to allow — Free is Community Edition and allows 0 stacks
    (docs/modules/EDITIONS.md), which would leave this class with nothing
    to observe."""

    @pytest.fixture(scope="class", autouse=True)
    def _limit_of_one(self, module_db, licensed_instance):
        from app import models

        plan = (
            module_db.query(models.OrganizationPlan)
            .filter(models.OrganizationPlan.org_id == _s["org_id"])
            .first()
        )
        previous = plan.max_infra_instances
        plan.max_infra_instances = 1
        module_db.commit()
        yield
        plan.max_infra_instances = previous
        module_db.commit()

    def test_first_stack_within_limit(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/stacks/deploy",
            json={
                "name": "stack-1",
                "project_id": _s["pid"],
                "bind_to_project": True,
                "services": [],
                "links": [],
            },
        )
        assert r.status_code == 201, r.text

    def test_second_stack_beyond_limit_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/stacks/deploy",
            json={
                "name": "stack-2",
                "project_id": _s["pid"],
                "bind_to_project": True,
                "services": [],
                "links": [],
            },
        )
        assert r.status_code == 402, r.text

    def test_unbound_standalone_stack_not_counted_against_limit(self, module_client: TestClient):
        # Standalone stacks (no project) can't be attributed to an org
        # today — deliberately out of scope for this limit, see
        # docs/modules/LICENSING_TZ.md ФТ-1.
        r = module_client.post(
            "/api/infra-v2/stacks/deploy",
            json={"name": "stack-standalone", "bind_to_project": False, "services": [], "links": []},
        )
        assert r.status_code == 201, r.text


@pytest.mark.usefixtures("licensed_instance")
class TestWorkstationGating:
    """ФТ-17: workstations were previously ungated — a Free org
    (max_workstations=0, no WORKSTATIONS feature) could spin up unlimited
    workstations. The feature gate runs before any provisioning, so a Free
    org is rejected with 402 before a template is even loaded.

    licensed_instance: without it the class depends on whatever license
    state earlier modules left in the shared singleton (tokens uploaded
    with module-scoped monkeypatched verifier keys) — intermittently
    lapsed, which made _set_tier 402 and has_feature flip to Free
    (order/timing flake on the Postgres runs, 2026-10-13)."""

    def test_free_org_denied_workstation(self, module_client: TestClient):
        _set_tier(module_client, _s["org_id"], "free")
        r = module_client.post(
            "/api/workstations",
            json={"project_id": _s["pid"], "template_id": "tmpl-bogus", "name": "ws-1"},
        )
        assert r.status_code == 402, r.text

    def test_team_passes_feature_and_limit_gate(self, module_client: TestClient, module_db):
        from app.core.plan import PlanFeature, check_workstation_limit, has_feature

        _set_tier(module_client, _s["org_id"], "team")
        assert has_feature(_s["org_id"], PlanFeature.WORKSTATIONS, module_db) is True
        # Team allows 5; none created yet, so adding up to 5 is allowed, 6 not.
        assert check_workstation_limit(_s["org_id"], module_db, adding=5) is True
        assert check_workstation_limit(_s["org_id"], module_db, adding=6) is False
        _set_tier(module_client, _s["org_id"], "free")

    def test_free_limit_is_zero(self, module_client: TestClient, module_db):
        from app.core.plan import check_workstation_limit

        _set_tier(module_client, _s["org_id"], "free")
        assert check_workstation_limit(_s["org_id"], module_db, adding=1) is False


@pytest.mark.usefixtures("licensed_instance")
@pytest.mark.ee
class TestProviderTierAtUse:
    """ФТ-17 / D1: a provider registered under a higher tier stops
    provisioning once the license drops below its tier — checked at use,
    not only at registration."""

    def test_provision_node_rechecks_provider_tier(self, module_client: TestClient):
        _set_tier(module_client, _s["org_id"], "enterprise")
        r = module_client.post(
            "/api/infra-v2/providers",
            json={"name": "aws-prov", "type": "aws", "org_id": _s["org_id"], "category": "cloud"},
        )
        assert r.status_code == 201, r.text
        prov_id = r.json()["id"]

        # Downgrade below the provider's tier: using it must now be blocked.
        _set_tier(module_client, _s["org_id"], "pro")
        r = module_client.post(
            f"/api/infra-v2/providers/{prov_id}/provision-node", json={"name": "n1"}
        )
        assert r.status_code == 402, r.text
        _set_tier(module_client, _s["org_id"], "free")


@pytest.mark.ee
class TestDnsManagementGating:
    def test_unlicensed_instance_denied_dns_record(self, module_client: TestClient, module_db):
        # Platform-level zone (provider not org-scoped): DNS management is
        # gated against the instance entitlement, which is Free/unlicensed
        # here, so record creation is refused.
        from app import models
        from app.core.utils import new_id, ts_now

        prov = models.InfraProvider(
            id=new_id("prov"), name="cf", type="cloudflare", category="dns",
            org_id=None, status="active", created_at=ts_now(),
        )
        module_db.add(prov)
        module_db.flush()
        zone = models.DnsZone(
            id=new_id("zone"), provider_id=prov.id, zone_name="ex.com", authorized=True,
        )
        module_db.add(zone)
        module_db.commit()

        r = module_client.post(
            f"/api/infra-v2/dns/zones/{zone.id}/records",
            json={"name": "a", "record_type": "A", "value": "1.2.3.4", "ttl": 300},
        )
        assert r.status_code == 402, r.text


@pytest.mark.ee
class TestCustomTemplatesGating:
    def test_unlicensed_instance_denied_template_create(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/templates",
            json={"name": "t1", "type": "custom", "image_ref": "nginx:latest"},
        )
        assert r.status_code == 402, r.text

    def test_unlicensed_instance_denied_blueprint_create(self, module_client: TestClient):
        r = module_client.post(
            "/api/infra-v2/blueprints",
            json={"name": "bp1", "description": "d", "services": [], "links": []},
        )
        assert r.status_code == 402, r.text


@pytest.mark.usefixtures("licensed_instance")
@pytest.mark.ee
class TestOverLimitReadOnly:
    """D1: after a downgrade, stacks/workstations beyond the new limit stay
    but become read-only — the over-limit ones can't be re-applied /
    re-provisioned, while destroy and reads still work."""

    def test_over_limit_stack_ids_marks_newest_excess(self, module_client: TestClient, module_db):
        from app.core.plan import over_limit_stack_ids
        from app.core.utils import new_id, ts_now
        from app.models.infra_v2 import InfraStack

        r = module_client.post("/api/orgs", json={"name": "D1 Org", "slug": "d1-org"})
        org_id = r.json()["id"]
        r = module_client.post(
            "/api/projects",
            json={"name": "D1 P", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        pid = r.json()["id"]
        module_client.patch(f"/api/projects/{pid}", json={"org_id": org_id})
        _set_tier(module_client, org_id, "free")
        _pin_infra_limit(module_db, org_id, 1)

        ids = []
        for i in range(3):
            s = InfraStack(id=new_id("stk"), name=f"s{i}", project_id=pid,
                           status="active", created_at=ts_now() + f"-{i}")
            module_db.add(s)
            ids.append(s.id)
        module_db.commit()

        over = over_limit_stack_ids(org_id, module_db)
        # Allowance of 1: the two newest are over-limit, the oldest is not.
        assert ids[0] not in over
        assert ids[1] in over and ids[2] in over

    def test_apply_blocked_on_over_limit_stack(self, module_client: TestClient, module_db):
        from app.core.utils import new_id, ts_now
        from app.models.infra_v2 import InfraStack

        r = module_client.post("/api/orgs", json={"name": "D1 Org2", "slug": "d1-org2"})
        org_id = r.json()["id"]
        r = module_client.post(
            "/api/projects",
            json={"name": "D1 P2", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        pid = r.json()["id"]
        module_client.patch(f"/api/projects/{pid}", json={"org_id": org_id})
        _set_tier(module_client, org_id, "free")
        _pin_infra_limit(module_db, org_id, 1)

        old = InfraStack(id=new_id("stk"), name="keep", project_id=pid, status="active", created_at=ts_now() + "-0")
        new = InfraStack(id=new_id("stk"), name="excess", project_id=pid, status="active", created_at=ts_now() + "-9")
        module_db.add(old)
        module_db.add(new)
        module_db.commit()

        # The over-limit (newest) stack is read-only — apply is refused.
        r = module_client.post(f"/api/infra-v2/stacks/{new.id}/apply", json={"services": []})
        assert r.status_code == 402, r.text
        # The within-limit (oldest) stack passes the D1 gate (it may then
        # fail later in real provisioning, which isn't what this asserts —
        # only that the gate itself doesn't block it).
        from app.core.plan import over_limit_stack_ids

        assert old.id not in over_limit_stack_ids(org_id, module_db)


class TestMultipleOrgsLimit:
    """MULTIPLE_ORGS (Pro+): more than one org per instance is gated.

    check_org_limit bypasses under APP_ENV=test (shared in-memory DB), so
    this overrides APP_ENV to exercise the real production logic directly.
    """

    def test_unlicensed_free_capped_at_one_org(self, module_db, monkeypatch):
        from app.core import plan

        monkeypatch.setenv("APP_ENV", "prod")
        # Fresh suite DB already has orgs from earlier classes → count >= 1,
        # and unlicensed instance lacks MULTIPLE_ORGS → creating another is denied.
        assert plan.check_org_limit(module_db) is False

    def test_pro_allows_multiple_orgs(self, module_db, module_client, module_monkeypatch, monkeypatch):
        from app.core import plan
        from tests._license_test_utils import license_instance, reset_instance_license

        monkeypatch.setenv("APP_ENV", "prod")
        license_instance(module_client, module_db, module_monkeypatch, tier="pro")
        try:
            assert plan.check_org_limit(module_db) is True
        finally:
            reset_instance_license(module_db)
