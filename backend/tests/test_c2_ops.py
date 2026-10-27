"""C2 operations API — listeners on demand + payload generation into Loot.

Pins the reverse-engineered Adaptix contract (listener_name as a JSON
ARRAY on /agent/generate; base64 "name:content" reply) and the platform
behaviour around it: live k8s Service port patch, TLS routed to the
redirector, payload lands in Loot with sha256.
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.c2ops.ops import DEFAULT_AGENT_CONFIG, create_listener
from app.core.utils import new_id, ts_now
from app.models import GlobalSetting
from app.models.infra_v2 import InfraProvider, InfraStack, ServiceLink, StackService

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _make_env(db, with_redirector=True):
    prv = InfraProvider(
        id=new_id("prv"), name="edge", type="manual", category="cloud",
        host="203.0.113.60", public_host="203.0.113.60", created_at=ts_now(),
    )
    db.add(prv)
    stack = InfraStack(
        id=new_id("stk"), name=f"c2ops-{new_id('s')[:6]}", status="ready",
        mode="standalone", created_at=ts_now(),
    )
    db.add(stack)
    db.flush()
    c2 = StackService(
        id=new_id("svc"), stack_id=stack.id, provider_id=prv.id, role="c2",
        name="adaptix-c2", status="running", ports=[{"external": 8443, "internal": 8443}],
        connection_url="https://203.0.113.60:8443",
    )
    db.add(c2)
    redir = None
    if with_redirector:
        redir = StackService(
            id=new_id("svc"), stack_id=stack.id, provider_id=prv.id, role="redirector",
            name="edge-redir", status="running", ports=[{"external": 443, "internal": 8443}],
        )
        db.add(redir)
        db.flush()
        db.add(
            ServiceLink(
                id=new_id("lnk"), stack_id=stack.id,
                from_service_id=redir.id, to_service_id=c2.id,
                link_type="http_proxy", status="configured",
            )
        )
    item = db.query(GlobalSetting).filter(GlobalSetting.key == "c2_integrations").first()
    value = item.value if item and isinstance(item.value, list) else []
    integration = {
        "id": new_id("c2"), "name": f"adaptix ({stack.name})", "type": "adaptix",
        "url": "https://203.0.113.60:8443", "username": "admin", "password": "plainpwd",
        "endpoint": "/endpoint", "enabled": True,
        "stack_id": stack.id, "service_id": c2.id,
        "project_ids": [],
    }
    value.append(integration)
    if item:
        item.value = value
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(item, "value")
    else:
        db.add(GlobalSetting(key="c2_integrations", value=value))
    db.commit()
    return integration, c2, redir


class TestCreateListener:
    def test_tls_routes_to_redirector(self, module_client, module_db):
        integration, c2, redir = _make_env(module_db)
        _state["iid"] = integration["id"]

        created = {}

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "t"}, text="x")
            if url.endswith("/listener/create"):
                created.update(kw["json"])
                cfg = json.loads(created["config"])
                assert cfg["port_bind"] == 9090
                assert cfg["ssl"] is False, "redirector present -> TLS terminates on nginx"
                assert cfg["x-forwarded-for"] is True
                return MagicMock(status_code=200, json=lambda: {"ok": True}, text="x")
            raise AssertionError(url)

        with (
            patch("app.core.c2ops.ops.httpx.Client") as MC,
            patch("app.core.c2ops.ops.expose_port", return_value={"ok": True, "mode": "test"}),
        ):
            inst = MagicMock()
            inst.post.side_effect = fake_post
            MC.return_value = inst
            r = module_client.post(
                f"/api/infra-v2/c2/{integration['id']}/listeners",
                json={"name": "ops-http", "port": 9090, "domain": "cd n.example.com".replace(" ", "")},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["tls"]["terminated_at"] == "redirector"
        assert body["tls"]["redirector"] == "edge-redir"
        assert created["type"] == "BeaconHTTP"

    def test_direct_k8s_callback_uses_nodeport(self, module_client, module_db):
        integration, c2, _ = _make_env(module_db, with_redirector=False)
        seen = {}

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "t"}, text="x")
            seen["config"] = kw["json"]["config"]
            return MagicMock(status_code=200, json=lambda: {"ok": True}, text="x")

        with (
            patch("app.core.c2ops.ops.httpx.Client") as MC,
            patch(
                "app.core.c2ops.ops.expose_port",
                return_value={"ok": True, "node_port": 31234, "node_host": "203.0.113.60", "mode": "k8s-live-patch"},
            ),
        ):
            inst = MagicMock()
            inst.post.side_effect = fake_post
            MC.return_value = inst
            r = module_client.post(
                f"/api/infra-v2/c2/{integration['id']}/listeners",
                json={"name": "np-cb", "port": 9443},
            )
        assert r.status_code == 200, r.text
        cfg = json.loads(seen["config"])
        assert cfg["callback_addresses"] == ["203.0.113.60:31234"], (
            "beacon callback must carry the live-patched NodePort, not the internal port"
        )

    def test_redirector_callback_points_at_redirector(self, module_client, module_db):
        integration, c2, redir = _make_env(module_db, with_redirector=True)
        seen = {}

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "t"}, text="x")
            seen["config"] = kw["json"]["config"]
            return MagicMock(status_code=200, json=lambda: {"ok": True}, text="x")

        with (
            patch("app.core.c2ops.ops.httpx.Client") as MC,
            patch("app.core.c2ops.ops.expose_port", return_value={"ok": True, "mode": "test"}),
        ):
            inst = MagicMock()
            inst.post.side_effect = fake_post
            MC.return_value = inst
            r = module_client.post(
                f"/api/infra-v2/c2/{integration['id']}/listeners",
                json={"name": "redir-cb", "port": 9444},
            )
        assert r.status_code == 200, r.text
        cfg = json.loads(seen["config"])
        # redirector provider public_host 203.0.113.60, external port 443
        assert cfg["callback_addresses"] == ["203.0.113.60:443"], (
            "behind a redirector the beacon must call the redirector, per the stack link"
        )
        assert cfg["ssl"] is False

    def test_no_redirector_listener_owns_tls(self, module_client, module_db):
        integration, c2, _ = _make_env(module_db, with_redirector=False)
        seen = {}

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "t"}, text="x")
            seen["config"] = kw["json"]["config"]
            return MagicMock(status_code=200, json=lambda: {"ok": True}, text="x")

        with (
            patch("app.core.c2ops.ops.httpx.Client") as MC,
            patch("app.core.c2ops.ops.expose_port", return_value={"ok": True, "mode": "test"}),
        ):
            inst = MagicMock()
            inst.post.side_effect = fake_post
            MC.return_value = inst
            r = module_client.post(
                f"/api/infra-v2/c2/{integration['id']}/listeners",
                json={"name": "direct-tls", "port": 443},
            )
        assert r.status_code == 200
        assert json.loads(seen["config"])["ssl"] is True


class TestPortConflict:
    def test_teamserver_port_rejected_with_suggestion(self, module_client, module_db):
        from fastapi import HTTPException

        integration, c2, _ = _make_env(module_db, with_redirector=False)
        c2.ports = [{"external": 8443, "internal": 8443}]
        module_db.commit()

        with patch("app.core.c2ops.ops.httpx.Client") as MC:
            inst = MagicMock()
            inst.get.return_value = MagicMock(status_code=200, json=lambda: [], text="[]")
            MC.return_value = inst
            try:
                create_listener(module_db, integration, {"name": "x", "port": 8443})
                raised = None
            except HTTPException as e:
                raised = e
        assert raised is not None and raised.status_code == 409
        assert "8443" in raised.detail and "8444" in raised.detail


class TestGeneratePayload:
    def test_listener_name_is_array_and_loot_created(self, module_client, module_db):
        from app.models import Loot

        integration, c2, _ = _make_env(module_db)
        sent = {}

        def fake_post(url, **kw):
            if url.endswith("/login"):
                return MagicMock(status_code=200, json=lambda: {"access_token": "t"}, text="x")
            assert url.endswith("/agent/generate")
            sent.update(kw["json"])
            assert isinstance(sent["listener_name"], list), "server 404s on a bare string"
            packed = (
                base64.b64encode(b"agent.x64.exe").decode()
                + ":"
                + base64.b64encode(b"MZfakepayload").decode()
            )
            return MagicMock(status_code=200, json=lambda: {"ok": True, "message": packed}, text="x")

        with (
            patch("app.core.c2ops.ops._login", return_value=(MagicMock(), "http://x", {"Authorization": "Bearer t"})) as _lg,
            patch("app.core.c2ops.ops.httpx.Client") as MC,
            patch("app.core.c2ops.ops.get_integration", return_value=integration),
        ):
            inst = MagicMock()
            inst.post.side_effect = fake_post
            MC.return_value = inst
            r = module_client.post(
                f"/api/infra-v2/c2/{integration['id']}/payloads",
                json={"listener": "ops-http", "agent": "beacon"},
            )
        assert r.status_code == 502 or r.status_code == 400, "no project bound -> explicit error"

        # bind a project and retry
        pr = module_client.post(
            "/api/projects", json={"name": f"C2Ops{new_id('p')[:6]}", "added": "2025-01-01T00:00:00Z"}
        )
        pid = pr.json()["id"]
        inst = MagicMock()
        inst.post.side_effect = fake_post
        with (
            patch("app.core.c2ops.ops._login", return_value=(inst, "http://x", {"Authorization": "Bearer t"})),
            patch("app.core.c2ops.ops.get_integration", return_value=integration),
        ):
            r = module_client.post(
                f"/api/infra-v2/c2/{integration['id']}/payloads",
                json={"listener": "ops-http", "pid": pid, "config": {"arch": "x86"}},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["filename"] == "agent.x64.exe"
        assert body["size"] == 13
        loot = module_db.query(Loot).get(body["loot_id"])
        assert loot is not None
        assert loot.loot_type == "payload"
        assert loot.sha256
        assert "ops-http" in loot.value

    def test_default_config_shape(self):
        assert DEFAULT_AGENT_CONFIG["arch"] == "x64"
        assert DEFAULT_AGENT_CONFIG["format"] == "Exe"
        assert set(DEFAULT_AGENT_CONFIG) == {
            "arch", "format", "sleep", "jitter", "dns_resolvers", "dns_mode",
            "doh_resolvers", "user_agent", "is_killdate", "kill_date", "kill_time",
            "is_workingtime", "start_time", "end_time", "svcname", "is_sideloading",
            "sideloading_content",
        }
