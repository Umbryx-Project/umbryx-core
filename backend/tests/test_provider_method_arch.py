"""
Tests for the new CloudProvider + DeployMethod architecture.

Covers:
  - CloudProviderRegistry mechanics (registration, lookup, schema, categories)
  - DeployMethodRegistry mechanics (registration, lookup, compatibility)
  - Provider adapter schemas (fields, types, required flags)
  - SSH method preview/deploy/destroy logic
  - Hetzner provider connect with invalid credentials
  - API endpoints (catalog, schema, deploy-methods, compatibility)
"""
import pytest
from fastapi.testclient import TestClient

from ._license_test_utils import license_ee

# Enterprise-only: every test here exercises the cloud-provider and
# deploy-method registries, which a Community build cannot do. Skipped
# there rather than failed — see
# conftest.py::pytest_collection_modifyitems.
pytestmark = pytest.mark.ee



ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    # Deployment is Enterprise-only (docs/modules/EDITIONS.md): these
    # tests drive it, so the instance has to hold a real license.
    undo = license_ee(module_client, module_db)
    yield
    undo()
    c.post("/api/auth/logout")


# ═══════════════════════════════════════════
# REGISTRY MECHANICS
# ═══════════════════════════════════════════

class TestCloudProviderRegistry:
    def test_builtin_providers_registered(self):
        from app.ee.infra import CloudProviderRegistry
        types = CloudProviderRegistry.list_types()
        assert "ssh_host" in types
        assert "hetzner" in types
        assert "proxmox" in types

    def test_get_returns_instance(self):
        from app.ee.infra import CloudProviderRegistry
        p = CloudProviderRegistry.get("hetzner")
        assert p is not None
        assert p.get_type() == "hetzner"

    def test_get_unknown_returns_none(self):
        from app.ee.infra import CloudProviderRegistry
        assert CloudProviderRegistry.get("nonexistent") is None

    def test_has(self):
        from app.ee.infra import CloudProviderRegistry
        assert CloudProviderRegistry.has("ssh_host") is True
        assert CloudProviderRegistry.has("xyz") is False

    def test_list_by_category(self):
        from app.ee.infra import CloudProviderRegistry
        cats = CloudProviderRegistry.list_by_category()
        assert "cloud" in cats
        assert "ssh_host" in cats
        cloud_types = [p["type"] for p in cats["cloud"]]
        assert "hetzner" in cloud_types

    def test_get_schema(self):
        from app.ee.infra import CloudProviderRegistry
        schema = CloudProviderRegistry.get_schema("hetzner")
        assert isinstance(schema, list)
        assert len(schema) > 0
        field_names = [f["name"] for f in schema]
        assert "api_token" in field_names

    def test_get_schema_unknown(self):
        from app.ee.infra import CloudProviderRegistry
        assert CloudProviderRegistry.get_schema("xyz") == []


class TestDeployMethodRegistry:
    def test_builtin_methods_registered(self):
        from app.ee.infra import DeployMethodRegistry
        types = DeployMethodRegistry.list_types()
        assert "ssh" in types
        assert "docker" in types
        assert "k8s" in types

    def test_get_returns_instance(self):
        from app.ee.infra import DeployMethodRegistry
        m = DeployMethodRegistry.get("ssh")
        assert m is not None
        assert m.get_type() == "ssh"

    def test_get_unknown_returns_none(self):
        from app.ee.infra import DeployMethodRegistry
        assert DeployMethodRegistry.get("nonexistent") is None

    def test_has(self):
        from app.ee.infra import DeployMethodRegistry
        assert DeployMethodRegistry.has("ssh") is True
        assert DeployMethodRegistry.has("xyz") is False

    def test_list_all(self):
        from app.ee.infra import DeployMethodRegistry
        all_methods = DeployMethodRegistry.list_all()
        assert isinstance(all_methods, list)
        types = [m["type"] for m in all_methods]
        assert "ssh" in types
        for m in all_methods:
            assert "name" in m
            assert "providers" in m
            assert isinstance(m["providers"], list)

    def test_get_for_provider(self):
        from app.ee.infra import DeployMethodRegistry
        ssh_host_methods = DeployMethodRegistry.get_for_provider("ssh_host")
        assert "ssh" in ssh_host_methods
        assert "docker" in ssh_host_methods
        assert "k8s" in ssh_host_methods
        assert "terraform" not in ssh_host_methods

    def test_get_for_cloud_provider(self):
        from app.ee.infra import DeployMethodRegistry
        hetzner_methods = DeployMethodRegistry.get_for_provider("hetzner")
        assert "ssh" in hetzner_methods
        assert "terraform" in hetzner_methods

    def test_is_compatible(self):
        from app.ee.infra import DeployMethodRegistry
        assert DeployMethodRegistry.is_compatible("ssh", "ssh_host") is True
        assert DeployMethodRegistry.is_compatible("terraform", "hetzner") is True
        assert DeployMethodRegistry.is_compatible("terraform", "ssh_host") is False
        assert DeployMethodRegistry.is_compatible("xyz", "hetzner") is False


# ═══════════════════════════════════════════
# PROVIDER ADAPTER SCHEMAS
# ═══════════════════════════════════════════

class TestProviderSchemas:
    def test_hetzner_schema(self):
        from app.ee.infra import CloudProviderRegistry
        schema = CloudProviderRegistry.get_schema("hetzner")
        field_map = {f["name"]: f for f in schema}
        assert "api_token" in field_map
        assert field_map["api_token"]["type"] == "password"
        assert field_map["api_token"]["required"] is True
        assert field_map["api_token"]["secret"] is True

    def test_ssh_host_schema(self):
        from app.ee.infra import CloudProviderRegistry
        schema = CloudProviderRegistry.get_schema("ssh_host")
        field_map = {f["name"]: f for f in schema}
        assert "host" in field_map
        assert "ssh_user" in field_map
        assert "ssh_key" in field_map

    def test_proxmox_schema(self):
        from app.ee.infra import CloudProviderRegistry
        schema = CloudProviderRegistry.get_schema("proxmox")
        field_map = {f["name"]: f for f in schema}
        assert "host" in field_map
        assert "api_token_id" in field_map
        assert "api_token_secret" in field_map

    def test_all_schemas_are_valid(self):
        from app.ee.infra import CloudProviderRegistry
        for ptype in CloudProviderRegistry.list_types():
            schema = CloudProviderRegistry.get_schema(ptype)
            assert isinstance(schema, list)
            for field in schema:
                assert "name" in field
                assert "label" in field
                assert "type" in field
                assert "required" in field
                assert "secret" in field


# ═══════════════════════════════════════════
# PROVIDER CONNECT (ERROR HANDLING)
# ═══════════════════════════════════════════

class TestProviderConnect:
    def test_hetzner_connect_invalid_token(self):
        from app.ee.infra import CloudProviderRegistry
        p = CloudProviderRegistry.get("hetzner")
        result = p.connect({"api_token": "invalid-token-xyz"})
        assert result["ok"] is False
        assert "message" in result

    def test_ssh_host_connect_no_host(self):
        from app.ee.infra import CloudProviderRegistry
        p = CloudProviderRegistry.get("ssh_host")
        result = p.connect({"host": ""})
        assert result["ok"] is False

    def test_ssh_host_connect_unreachable(self):
        from unittest.mock import MagicMock, patch

        from app.ee.infra import CloudProviderRegistry
        p = CloudProviderRegistry.get("ssh_host")
        mock_client = MagicMock()
        mock_client.connect.side_effect = OSError("unreachable")
        with patch("paramiko.SSHClient", return_value=mock_client):
            result = p.connect({"host": "10.255.255.1", "port": 22, "ssh_user": "root", "ssh_key": ""})
        assert result["ok"] is False

    def test_hetzner_list_resources_empty_with_bad_token(self):
        from app.ee.infra import CloudProviderRegistry
        p = CloudProviderRegistry.get("hetzner")
        resources = p.list_resources({"api_token": "bad"})
        assert isinstance(resources, list)
        assert len(resources) == 0


# ═══════════════════════════════════════════
# SSH DEPLOY METHOD
# ═══════════════════════════════════════════

class TestSSHMethod:
    def _make_ctx(self):
        from app.ee.infra.deploy_method import DeployContext
        return DeployContext(
            stack_id="stk_test01",
            stack_name="test-stack",
            service_id="svc_test01",
            service_name="test-svc",
            role="c2",
            image="nginx:alpine",
            config={},
            ports=[{"external": 8080, "internal": 80, "proto": "tcp"}],
            env={"DEBUG": "true"},
            volumes=[],
            domain="",
        )

    def _make_target(self):
        from app.ee.infra.deploy_method import DeployTarget
        return DeployTarget(
            provider_type="ssh_host",
            host="10.255.255.1",
            port=22,
            ssh_user="root",
            ssh_key="",
        )

    def test_preview_generates_command(self):
        from app.ee.infra.deploy_method import DeployMethodRegistry
        m = DeployMethodRegistry.get("ssh")
        ctx = self._make_ctx()
        target = self._make_target()
        result = m.preview(ctx, target)
        assert result.success is True
        assert "docker run" in result.plan
        assert "nginx:alpine" in result.plan
        assert "-p 8080:80/tcp" in result.plan
        assert "-e DEBUG=true" in result.plan

    def test_deploy_unreachable_host(self):
        from unittest.mock import MagicMock, patch

        from app.ee.infra.deploy_method import DeployMethodRegistry
        m = DeployMethodRegistry.get("ssh")
        mock_client = MagicMock()
        mock_client.connect.side_effect = OSError("unreachable")
        with patch("paramiko.SSHClient", return_value=mock_client):
            result = m.test_connection(self._make_target())
        assert result["ok"] is False

    def test_status_unreachable_host(self):
        from unittest.mock import MagicMock, patch

        from app.ee.infra.deploy_method import DeployMethodRegistry
        m = DeployMethodRegistry.get("ssh")
        mock_client = MagicMock()
        mock_client.connect.side_effect = OSError("unreachable")
        with patch("paramiko.SSHClient", return_value=mock_client):
            result = m.test_connection(self._make_target())
        assert "ok" in result

    def test_get_logs_unreachable(self):
        from app.ee.infra.deploy_method import DeployMethodRegistry
        m = DeployMethodRegistry.get("ssh")
        ctx = self._make_ctx()
        result = m.preview(ctx, self._make_target())
        assert result.success is True


# ═══════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════

class TestAPIProviderCatalog:
    def test_get_catalog(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/providers/catalog")
        assert r.status_code == 200
        data = r.json()
        assert "categories" in data
        cats = {c["category"]: c["providers"] for c in data["categories"]}
        assert "cloud" in cats
        assert "ssh_host" in cats
        cloud_types = [p["type"] for p in cats["cloud"]]
        assert "hetzner" in cloud_types

    def test_catalog_has_schema(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/providers/catalog")
        data = r.json()
        for cat in data["categories"]:
            for prov in cat["providers"]:
                assert "credentials_schema" in prov
                assert isinstance(prov["credentials_schema"], list)

    def test_get_schema_for_hetzner(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/providers/hetzner/schema")
        assert r.status_code == 200
        data = r.json()
        schema = data.get("schema", data) if isinstance(data, dict) else data
        assert isinstance(schema, list)
        names = [f["name"] for f in schema]
        assert "api_token" in names

    def test_get_schema_unknown(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/providers/nonexistent/schema")
        assert r.status_code in (200, 404)


class TestAPIDeployMethods:
    def test_get_deploy_methods(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/deploy-methods")
        assert r.status_code == 200
        data = r.json()
        assert "methods" in data
        types = [m["type"] for m in data["methods"]]
        assert "ssh" in types
        assert "docker" in types
        assert "k8s" in types

    def test_methods_have_display_names(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/deploy-methods")
        for m in r.json()["methods"]:
            assert m["name"]
            assert len(m["name"]) > 0

    def test_get_methods_for_provider(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/deploy-methods/for/hetzner")
        assert r.status_code == 200
        data = r.json()
        methods = data.get("methods", data) if isinstance(data, dict) else data
        types = [m["type"] for m in methods]
        assert "ssh" in types
        assert "terraform" in types

    def test_get_methods_for_ssh_host(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/deploy-methods/for/ssh_host")
        assert r.status_code == 200
        data = r.json()
        methods = data.get("methods", data) if isinstance(data, dict) else data
        types = [m["type"] for m in methods]
        assert "ssh" in types
        assert "docker" in types
        assert "terraform" not in types

    def test_get_methods_for_unknown_provider(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/deploy-methods/for/nonexistent")
        assert r.status_code == 200
        data = r.json()
        methods = data.get("methods", data) if isinstance(data, dict) else data
        assert len(methods) == 0


class TestAPICompatibility:
    def test_compatibility_matrix(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/compatibility")
        assert r.status_code == 200
        data = r.json()
        assert "matrix" in data
        mx = data["matrix"]
        assert "hetzner" in mx
        assert "ssh" in mx["hetzner"]
        assert "terraform" in mx["hetzner"]
        assert "ssh_host" in mx
        assert "terraform" not in mx.get("ssh_host", [])

    def test_compatibility_consistency(self, module_client: TestClient):
        r = module_client.get("/api/infra-v2/compatibility")
        mx = r.json()["matrix"]
        methods_r = module_client.get("/api/infra-v2/deploy-methods")
        method_providers = {m["type"]: set(m["providers"]) for m in methods_r.json()["methods"]}
        for provider_type, methods in mx.items():
            for method_type in methods:
                assert provider_type in method_providers.get(method_type, set()), \
                    f"{method_type} lists {provider_type} in matrix but not in supported_provider_types"


# ═══════════════════════════════════════════
# CHECK PROVIDER (via new CloudProvider bridge)
# ═══════════════════════════════════════════

class TestCheckProvider:
    def test_check_ssh_provider_uses_bridge(self, module_client: TestClient):
        from unittest.mock import MagicMock, patch
        pid = module_client.post("/api/infra-v2/providers", json={
            "name": "test-ssh-bridge",
            "type": "ssh",
            "category": "ssh_host",
            "host": "10.255.255.1",
            "port": 22,
            "ssh_user": "root",
            "deploy_mode": "ssh",
            "connection": {},
        }).json()["id"]

        mock_client = MagicMock()
        mock_client.connect.side_effect = OSError("unreachable")
        with patch("paramiko.SSHClient", return_value=mock_client):
            r = module_client.post(f"/api/infra-v2/providers/{pid}/check")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is False
        assert "SSH" in data["message"] or "ssh" in data["message"].lower()

        module_client.delete(f"/api/infra-v2/providers/{pid}")

    def test_check_hetzner_provider_uses_bridge(self, module_client: TestClient):
        pid = module_client.post("/api/infra-v2/providers", json={
            "name": "test-hetzner-bridge",
            "type": "hetzner",
            "category": "cloud",
            "deploy_mode": "ssh",
            "connection": {"api_token": "invalid-token-test"},
        }).json()["id"]

        r = module_client.post(f"/api/infra-v2/providers/{pid}/check")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is False

        module_client.delete(f"/api/infra-v2/providers/{pid}")

    def test_check_unknown_provider_fallback(self, module_client: TestClient):
        pid = module_client.post("/api/infra-v2/providers", json={
            "name": "test-manual",
            "type": "custom_type",
            "category": "cloud",
            "deploy_mode": "ssh",
            "connection": {},
        }).json()["id"]

        r = module_client.post(f"/api/infra-v2/providers/{pid}/check")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "manual" in data["message"].lower()

        module_client.delete(f"/api/infra-v2/providers/{pid}")
