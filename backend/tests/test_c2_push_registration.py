"""C2 push-registration of redirectors (Adaptix) — gap #2, ARCHITECTURE.md §3.

The Adaptix API contract these tests pin was reverse-engineered and
verified live against a real teamserver (test55 stand, 2026-09-15):
login -> /listener/list -> /listener/create with a JSON-*string* config
whose keys are the ax_config.axs container.put() names.
"""

import pytest

# Enterprise-only: this module imports app.ee at import time, so in a
# Community tree (where the package is removed by scripts/build-ce.sh)
# there is nothing to test rather than something failing. Declared here
# instead of in a list in conftest, so a module that stops depending on
# the Enterprise package can drop the line with it.
pytest.importorskip("app.ee", reason="Enterprise Edition package not in this build")

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.ee.infra.c2_push import register_redirector_listeners
from app.models import GlobalSetting
from app.models.infra_v2 import InfraProvider, InfraStack, ServiceLink, StackService

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _make_stack(db, with_redirector=True, with_integration=True):
    provider = InfraProvider(
        id=new_id("prv"),
        name="edge",
        type="manual",
        category="cloud",
        host="203.0.113.40",
        public_host="203.0.113.40",
        created_at=ts_now(),
    )
    db.add(provider)
    stack = InfraStack(
        id=new_id("stk"),
        name=f"push-{new_id('s')[:6]}",
        status="ready",
        mode="standalone",
        created_at=ts_now(),
    )
    db.add(stack)
    db.flush()
    c2 = StackService(
        id=new_id("svc"),
        stack_id=stack.id,
        provider_id=provider.id,
        role="c2",
        name="adaptix-server",
        status="running",
        ports=[{"external": 8443, "internal": 8443}],
        connection_url="https://203.0.113.40:8443",
    )
    db.add(c2)
    redir = None
    if with_redirector:
        redir = StackService(
            id=new_id("svc"),
            stack_id=stack.id,
            provider_id=provider.id,
            role="redirector",
            name="edge-redirector",
            status="running",
            ports=[{"external": 443, "internal": 8443}],
            connection_url="https://203.0.113.40:443",
        )
        db.add(redir)
        db.flush()
        db.add(
            ServiceLink(
                id=new_id("lnk"),
                stack_id=stack.id,
                from_service_id=redir.id,
                to_service_id=c2.id,
                link_type="http_proxy",
                status="configured",
            )
        )
    if with_integration:
        item = db.query(GlobalSetting).filter(GlobalSetting.key == "c2_integrations").first()
        value = item.value if item and isinstance(item.value, list) else []
        value.append(
            {
                "id": new_id("c2"),
                "name": f"adaptix ({stack.name})",
                "type": "adaptix",
                "url": "https://203.0.113.40:8443",
                "username": "admin",
                "password": "plainpwd",
                "endpoint": "/endpoint",
                "stack_id": stack.id,
                "service_id": c2.id,
                "enabled": True,
            }
        )
        if item:
            item.value = value
            from sqlalchemy.orm.attributes import flag_modified

            flag_modified(item, "value")
        else:
            db.add(GlobalSetting(key="c2_integrations", value=value))
    db.commit()
    return stack, c2, redir


def _steps(svc):
    return (svc.integration_steps or {}).get("c2_listener_registration", {})


class TestRegister:
    def test_creates_listener_with_correct_payload(self, module_client, module_db):
        stack, _c2, redir = _make_stack(module_db)
        created = {}

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "tok"}, text="x")
            if url.endswith("/listener/create"):
                created.update(kw["json"])
                return MagicMock(status_code=200, json=lambda: {"ok": True, "message": "Listener started"}, text="x")
            raise AssertionError(url)

        def fake_get(url, **kw):
            assert url.endswith("/listener/list")
            return MagicMock(status_code=200, json=lambda: None, text="null")

        with (
            patch("app.ee.infra.c2_push.httpx.Client") as MockClient,
        ):
            inst = MagicMock()
            inst.post.side_effect = fake_post
            inst.get.side_effect = fake_get
            MockClient.return_value.__enter__.return_value = inst

            ok = register_redirector_listeners(module_db, stack)

        assert ok is True
        assert created["name"] == "edge-redirector"
        assert created["type"] == "BeaconHTTP"
        cfg = created["config"]
        assert isinstance(cfg, str), "config must be a JSON string (client contract)"
        parsed = __import__("json").loads(cfg)
        assert parsed["port_bind"] == 8443, "binds on the C2 internal port the proxy targets"
        assert parsed["callback_addresses"] == ["203.0.113.40:443"], "beacons call the redirector"
        assert "<<<PAYLOAD_DATA>>>" in parsed["page-payload"]

        module_db.expire_all()
        step = _steps(module_db.query(StackService).get(redir.id))
        assert step["status"] == "done"

    def test_existing_listener_skipped(self, module_client, module_db):
        stack, _c2, redir = _make_stack(module_db)

        def fake_get(url, **kw):
            return MagicMock(
                status_code=200,
                json=lambda: [{"l_name": "edge-redirector", "l_status": "Listen"}],
                text="[]",
            )

        with patch("app.ee.infra.c2_push.httpx.Client") as MockClient:
            inst = MagicMock()
            inst.post.return_value = MagicMock(
                status_code=200, json=lambda: {"access_token": "tok"}, text="x"
            )
            inst.get.side_effect = fake_get
            MockClient.return_value.__enter__.return_value = inst
            ok = register_redirector_listeners(module_db, stack)

        assert ok is True
        module_db.expire_all()
        assert _steps(module_db.query(StackService).get(redir.id))["status"] == "done"
        assert "already" in _steps(module_db.query(StackService).get(redir.id))["message"]

    def test_rejected_creation_fails_pipeline(self, module_client, module_db):
        stack, _c2, redir = _make_stack(module_db)

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "tok"}, text="x")
            return MagicMock(
                status_code=200,
                json=lambda: {"ok": False, "message": "port already allocated"},
                text="x",
            )

        with patch("app.ee.infra.c2_push.httpx.Client") as MockClient:
            inst = MagicMock()
            inst.post.side_effect = fake_post
            inst.get.return_value = MagicMock(status_code=200, json=lambda: None, text="null")
            MockClient.return_value.__enter__.return_value = inst
            ok = register_redirector_listeners(module_db, stack)

        assert ok is False
        module_db.expire_all()
        assert _steps(module_db.query(StackService).get(redir.id))["status"] == "error"
        assert "port already allocated" in _steps(module_db.query(StackService).get(redir.id))["message"]

    def test_no_links_noop_true(self, module_client, module_db):
        stack, _c2, _redir = _make_stack(module_db, with_redirector=False)
        with patch("app.ee.infra.c2_push.httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MagicMock()
            assert register_redirector_listeners(module_db, stack) is True
            MockClient.assert_not_called()

    def test_no_integration_marks_skipped(self, module_client, module_db):
        stack, _c2, redir = _make_stack(module_db, with_integration=False)
        with patch("app.ee.infra.c2_push.httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MagicMock()
            assert register_redirector_listeners(module_db, stack) is True
            MockClient.assert_not_called()
        module_db.expire_all()
        assert _steps(module_db.query(StackService).get(redir.id))["status"] == "skipped"
