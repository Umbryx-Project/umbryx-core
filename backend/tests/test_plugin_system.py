"""
Phase 2.5 — Plugin & Extension System tests.
"""
import json
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db, module_monkeypatch):
    from ._license_test_utils import license_instance, reset_instance_license

    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    # Plugin install now requires the PLUGIN_UPLOAD feature (Pro+) — license
    # the instance so these tests exercise the install flow, not the gate.
    license_instance(c, module_db, module_monkeypatch, tier="pro")
    yield
    reset_instance_license(module_db)
    c.post("/api/auth/logout")


def _make_plugin_zip(
    plugin_id="test-plugin",
    version="1.0.0",
    api_version=1,
    title="Test Plugin",
    permissions=None,
    backend_code="",
    frontend_js="",
) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".rnplugin", delete=False)
    manifest = (
        f'[plugin]\nid = "{plugin_id}"\nversion = "{version}"\n'
        f'api_version = {api_version}\ntitle = "{title}"\n'
        f'description = "A test plugin"\nauthor = "Test"\nlicense = "MIT"\n'
    )
    if permissions:
        manifest += "\n[permissions]\n"
        for mode, keys in permissions.items():
            manifest += f'{mode} = {json.dumps(keys)}\n'

    with zipfile.ZipFile(tmp, "w") as zf:
        zf.writestr("plugin.toml", manifest)
        if backend_code:
            zf.writestr("backend/main.py", backend_code)
        if frontend_js:
            zf.writestr("frontend/index.js", frontend_js)

    tmp.close()
    return Path(tmp.name)


class TestPluginInstall:
    def test_install_valid_bundle(self, module_client: TestClient):
        bundle = _make_plugin_zip(title="My Plugin")
        try:
            with open(bundle, "rb") as f:
                r = module_client.post(
                    "/api/plugins/install",
                    files={"file": ("test.rnplugin", f, "application/zip")},
                )
            assert r.status_code == 200, r.text
            data = r.json()
            assert data["id"] == "test-plugin"
            assert data["version"] == "1.0.0"
            assert data["title"] == "My Plugin"
            _s["pid"] = data["id"]
        finally:
            bundle.unlink(missing_ok=True)

    def test_list_shows_installed(self, module_client: TestClient):
        r = module_client.get("/api/plugins")
        assert r.status_code == 200
        plugins = r.json()
        assert any(p["id"] == "test-plugin" for p in plugins)

    def test_install_duplicate_updates(self, module_client: TestClient):
        bundle = _make_plugin_zip(version="2.0.0", title="My Plugin v2")
        try:
            with open(bundle, "rb") as f:
                r = module_client.post(
                    "/api/plugins/install",
                    files={"file": ("test.rnplugin", f, "application/zip")},
                )
            assert r.status_code == 200
            assert r.json()["version"] == "2.0.0"
        finally:
            bundle.unlink(missing_ok=True)


class TestPluginToggle:
    def test_disable_plugin(self, module_client: TestClient):
        r = module_client.patch("/api/plugins/test-plugin", json={"enabled": False})
        assert r.status_code == 200
        assert r.json()["enabled"] is False

    def test_enable_plugin(self, module_client: TestClient):
        r = module_client.patch("/api/plugins/test-plugin", json={"enabled": True})
        assert r.status_code == 200
        assert r.json()["enabled"] is True


class TestPluginUninstall:
    def test_uninstall(self, module_client: TestClient):
        r = module_client.delete("/api/plugins/test-plugin")
        assert r.status_code == 200

    def test_uninstall_missing_404(self, module_client: TestClient):
        r = module_client.delete("/api/plugins/nonexistent")
        assert r.status_code == 404


class TestPluginValidation:
    def test_reject_non_zip(self, module_client: TestClient):
        tmp = tempfile.NamedTemporaryFile(suffix=".rnplugin", delete=False)
        tmp.write(b"not a zip")
        tmp.close()
        try:
            with open(tmp.name, "rb") as f:
                r = module_client.post(
                    "/api/plugins/install",
                    files={"file": ("bad.rnplugin", f, "application/zip")},
                )
            assert r.status_code == 400
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_reject_missing_manifest(self, module_client: TestClient):
        tmp = tempfile.NamedTemporaryFile(suffix=".rnplugin", delete=False)
        with zipfile.ZipFile(tmp, "w") as zf:
            zf.writestr("readme.txt", "hello")
        tmp.close()
        try:
            with open(tmp.name, "rb") as f:
                r = module_client.post(
                    "/api/plugins/install",
                    files={"file": ("bad.rnplugin", f, "application/zip")},
                )
            assert r.status_code == 400
            assert "plugin.toml" in r.text
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_reject_bad_api_version(self, module_client: TestClient):
        bundle = _make_plugin_zip(plugin_id="bad-api-ver", api_version=99)
        try:
            with open(bundle, "rb") as f:
                r = module_client.post(
                    "/api/plugins/install",
                    files={"file": ("bad.rnplugin", f, "application/zip")},
                )
            assert r.status_code == 400
            assert "api_version" in r.text.lower()
        finally:
            bundle.unlink(missing_ok=True)


class TestPluginFrontend:
    def test_no_frontend_404(self, module_client: TestClient):
        r = module_client.get("/api/plugins/test-plugin/frontend.js")
        assert r.status_code == 404

    def test_frontend_served(self, module_client: TestClient):
        bundle = _make_plugin_zip(
            plugin_id="frontend-plugin",
            frontend_js='export default { title: "FP" };',
        )
        try:
            with open(bundle, "rb") as f:
                r = module_client.post(
                    "/api/plugins/install",
                    files={"file": ("fp.rnplugin", f, "application/zip")},
                )
            assert r.status_code == 200

            r = module_client.get("/api/plugins/frontend-plugin/frontend.js")
            assert r.status_code == 200
            assert "export default" in r.text
        finally:
            module_client.delete("/api/plugins/frontend-plugin")
            bundle.unlink(missing_ok=True)


class TestEventBus:
    def test_subscribe_and_emit(self):
        from app.sdk.events import PluginEventBus
        bus = PluginEventBus()
        received = []
        bus.subscribe("test.event", lambda p: received.append(p))
        import asyncio
        asyncio.run(bus.emit("test.event", {"key": "val"}))
        assert len(received) == 1
        assert received[0]["key"] == "val"
        bus.clear()

    def test_decorator_subscribe(self):
        from app.sdk.events import PluginEventBus
        bus = PluginEventBus()
        received = []

        @bus.on("test.event2")
        async def handler(payload):
            received.append(payload)

        import asyncio
        asyncio.run(bus.emit("test.event2", {"x": 1}))
        assert len(received) == 1
        bus.clear()


class TestSDKContracts:
    def test_host_dto(self):
        from app.sdk.contracts import HostDTO
        h = HostDTO(id="h1", ip="10.0.0.1", hostname="test", tags=["a"], status="alive")
        assert h.id == "h1"
        assert h.ip == "10.0.0.1"

    def test_finding_dto(self):
        from app.sdk.contracts import FindingDTO
        f = FindingDTO(title="XSS", severity="high", host_id="h1")
        assert f.title == "XSS"
        assert f.severity == "high"

    def test_connector_result(self):
        from app.sdk.contracts import ConnectorResult
        r = ConnectorResult(ok=True, output="done")
        assert r.ok is True
        assert r.error is None
