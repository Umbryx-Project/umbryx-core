"""Own-infra host registration (ARCHITECTURE.md §3 known gap #1).

Deployed stack services must appear in the project's Host graph as
attacker-side hosts (tags own-infra / infra-stack:{sid}, external ports,
is_attacker=True on rows we create), be idempotent, merge into existing
hosts without flipping their semantics, and disappear on unregister —
via the engine's post-deploy pipeline and the bind/unbind endpoints.
"""

import pytest

# Enterprise-only: this module imports app.ee at import time, so in a
# Community tree (where the package is removed by scripts/build-ce.sh)
# there is nothing to test rather than something failing. Declared here
# instead of in a list in conftest, so a module that stops depending on
# the Enterprise package can drop the line with it.
pytest.importorskip("app.ee", reason="Enterprise Edition package not in this build")

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.ee.infra.host_registration import register_stack_hosts, unregister_stack_hosts
from app.models import Host
from app.models.infra_v2 import InfraProvider, InfraStack, StackService

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    # Deployment is Enterprise-only (docs/modules/EDITIONS.md): these
    # tests drive it, so the instance has to hold a real license.
    undo = license_ee(module_client, module_db)
    yield
    undo()


def _make_project(client):
    r = client.post(
        "/api/projects",
        json={"name": f"InfraHostProj{new_id('x')[:6]}", "added": "2025-01-01T00:00:00Z"},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _make_stack(db, pid, with_service=True, ip="203.0.113.10"):
    provider = InfraProvider(
        id=new_id("prv"),
        name="edge-node",
        type="manual",
        category="cloud",
        host=ip,
        public_host=ip,
        created_at=ts_now(),
    )
    db.add(provider)
    stack = InfraStack(
        id=new_id("stk"),
        project_id=pid,
        name=f"stack-{new_id('s')[:6]}",
        status="ready",
        mode="project" if pid else "standalone",
        bound_at=ts_now() if pid else None,
        created_at=ts_now(),
    )
    db.add(stack)
    db.flush()
    svc = None
    if with_service:
        svc = StackService(
            id=new_id("svc"),
            stack_id=stack.id,
            provider_id=provider.id,
            role="c2",
            name="adaptix-server",
            status="running",
            ports=[{"external": 443, "internal": 8443}, {"external": 80, "internal": 8080}],
        )
        db.add(svc)
    db.commit()
    return stack, svc, provider


class TestRegister:
    def test_register_creates_attacker_host(self, module_client, module_db):
        pid = _make_project(module_client)
        stack, svc, _ = _make_stack(module_db, pid)

        touched = register_stack_hosts(module_db, stack)
        assert touched == 1

        host = (
            module_db.query(Host)
            .filter(Host.pid == pid, Host.ip == "203.0.113.10")
            .first()
        )
        assert host is not None
        assert host.is_attacker is True
        assert host.import_source == "infra-stack"
        assert host.role == "infra"
        assert sorted(host.ports) == ["443/tcp", "80/tcp"]
        assert "own-infra" in host.tags
        assert f"infra-stack:{stack.id}" in host.tags
        assert "infra-role:c2" in host.tags
        assert any(s.startswith("c2:") for s in host.services)
        _state["pid"] = pid
        _state["stack_id"] = stack.id

    def test_register_is_idempotent_and_merges(self, module_client, module_db):
        stack = module_db.query(InfraStack).get(_state["stack_id"])
        assert register_stack_hosts(module_db, stack) == 1

        hosts = module_db.query(Host).filter(Host.pid == _state["pid"]).all()
        assert len(hosts) == 1
        assert sorted(hosts[0].ports) == ["443/tcp", "80/tcp"]  # no duplicates

    def test_existing_host_not_flipped_to_attacker(self, module_client, module_db):
        pid = _make_project(module_client)
        foreign = Host(
            id=new_id("hst"),
            pid=pid,
            ip="198.51.100.7",
            hostname="scanned-target",
            os="Windows",
            status="up",
            role="server",
            is_attacker=False,
            import_source="nmap",
            ports=["445/tcp"],
            tags=["windows"],
        )
        module_db.add(foreign)
        module_db.commit()
        stack, _, _ = _make_stack(module_db, pid, ip="198.51.100.7")

        register_stack_hosts(module_db, stack)

        module_db.expire_all()
        row = module_db.query(Host).get(foreign.id)
        assert row.is_attacker is False  # semantics preserved
        assert row.import_source == "nmap"
        assert "own-infra" in row.tags  # but tagged and ports merged
        assert "445/tcp" in row.ports
        assert f"infra-stack:{stack.id}" in row.tags

    def test_standalone_stack_is_noop(self, module_client, module_db):
        stack, _, _ = _make_stack(module_db, None)
        assert register_stack_hosts(module_db, stack) == 0


class TestUnregister:
    def test_unregister_deletes_own_row_keeps_foreign(self, module_client, module_db):
        pid = _make_project(module_client)
        # our row
        stack_own, _, _ = _make_stack(module_db, pid, ip="203.0.113.20")
        register_stack_hosts(module_db, stack_own)
        # foreign row sharing the stack tag (merge case)
        foreign = Host(
            id=new_id("hst"),
            pid=pid,
            ip="198.51.100.9",
            hostname="target",
            status="up",
            is_attacker=False,
            import_source="nmap",
            tags=["linux", f"infra-stack:{stack_own.id}"],
        )
        module_db.add(foreign)
        module_db.commit()

        affected = unregister_stack_hosts(module_db, stack_own)
        assert affected == 2

        module_db.expire_all()
        ours = (
            module_db.query(Host)
            .filter(Host.pid == pid, Host.ip == "203.0.113.20")
            .first()
        )
        assert ours.deleted_at is not None  # soft-deleted
        kept = module_db.query(Host).get(foreign.id)
        assert kept.deleted_at is None
        assert f"infra-stack:{stack_own.id}" not in kept.tags
        assert "linux" in kept.tags

    def test_unregister_shared_node_keeps_host_while_other_stack_tagged(
        self, module_client, module_db
    ):
        pid = _make_project(module_client)
        stack_a, _, _ = _make_stack(module_db, pid, ip="203.0.113.30")
        register_stack_hosts(module_db, stack_a)
        # second stack on the same node → same host gains its tag too
        stack_b, _, _ = _make_stack(module_db, pid, ip="203.0.113.30")
        register_stack_hosts(module_db, stack_b)

        hosts = (
            module_db.query(Host)
            .filter(Host.pid == pid, Host.ip == "203.0.113.30")
            .all()
        )
        assert len(hosts) == 1

        unregister_stack_hosts(module_db, stack_a)
        module_db.expire_all()
        row = (
            module_db.query(Host)
            .filter(Host.pid == pid, Host.ip == "203.0.113.30")
            .first()
        )
        assert row.deleted_at is None  # still serving stack_b
        assert f"infra-stack:{stack_a.id}" not in row.tags
        assert f"infra-stack:{stack_b.id}" in row.tags


class TestEndpoints:
    def test_bind_registers_unbind_unregisters(self, module_client, module_db):
        pid = _make_project(module_client)
        stack, svc, _ = _make_stack(module_db, None)  # standalone
        assert register_stack_hosts(module_db, stack) == 0  # no project yet

        r = module_client.post(
            f"/api/infra-v2/stacks/{stack.id}/bind", json={"project_id": pid}
        )
        assert r.status_code == 200, r.text
        host = (
            module_db.query(Host)
            .filter(Host.pid == pid, Host.ip == "203.0.113.10")
            .first()
        )
        assert host is not None
        assert host.is_attacker is True

        r = module_client.post(f"/api/infra-v2/stacks/{stack.id}/unbind")
        assert r.status_code == 200, r.text
        module_db.expire_all()
        host = (
            module_db.query(Host)
            .filter(Host.pid == pid, Host.ip == "203.0.113.10", Host.deleted_at.is_(None))
            .first()
        )
        assert host is None
