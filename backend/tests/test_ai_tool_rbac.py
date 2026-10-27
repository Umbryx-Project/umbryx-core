"""
RBAC enforcement for AI-chat tool execution.

The agent's tool-calling loop (core/ai/agent.py) has no notion of the
calling user's project role by itself — risk-based gating
(block_critical_tools / require_confirmation_writes) is a project-wide
safety toggle, not a permission check, and "confirmation" is just the
same low-privileged user clicking OK. Without tool_registry.execute()
itself checking required_permission, any project member able to open
an AI chat (gated only on "findings.read", which every role has) could
reach create_finding/add_host_tag/create_note/run_playbook through the
agent regardless of whether their role grants findings.create/
hosts.update/notes.create/command_outputs.create — bypassing the exact
same permission their role is denied on the direct REST routes.
"""
import pytest
from fastapi.testclient import TestClient

from app.core.ai.tool_registry import tool_registry

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "RolePass1234!"
_s: dict = {}


def _create_user(c: TestClient, username: str) -> str:
    r = c.post("/api/admin/users", json={"username": username, "password": USER_PASS, "role": "user"})
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


def _add_member(c: TestClient, pid: str, uid: str, role: str):
    r = c.post(f"/api/projects/{pid}/members", json={"user_id": uid, "role": role})
    assert r.status_code in (200, 201), f"add member {role}: {r.text}"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200

    # The review roles (reviewer / analyst / observer) are Team+
    # (docs/modules/MONETIZATION.md) and this module assigns them to
    # check what each role may do. A license, not an `ee` marker: the
    # roles exist in every build and are gated by the license, not
    # removed from the artifact.
    _s["_license_undo"] = license_ee(c, module_db)

    r = c.post("/api/projects", json={"name": "AI Tool RBAC", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    _s["viewer"] = _create_user(c, "ai_rbac_viewer")
    _s["auditor"] = _create_user(c, "ai_rbac_auditor")
    _s["operator"] = _create_user(c, "ai_rbac_operator")
    _s["editor"] = _create_user(c, "ai_rbac_editor")
    _s["reviewer"] = _create_user(c, "ai_rbac_reviewer")

    _add_member(c, _s["pid"], _s["viewer"], "viewer")
    _add_member(c, _s["pid"], _s["auditor"], "auditor")
    _add_member(c, _s["pid"], _s["operator"], "operator")
    _add_member(c, _s["pid"], _s["editor"], "editor")
    _add_member(c, _s["pid"], _s["reviewer"], "reviewer")

    r = c.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.9.1", "os": "linux"})
    assert r.status_code in (200, 201), r.text
    _s["host_id"] = r.json()["id"]

    yield
    _s.pop("_license_undo")()


class TestCreateFindingPermission:
    """create_finding is RiskLevel.WRITE, required_permission="findings.create"."""

    @pytest.mark.asyncio
    async def test_viewer_denied(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "create_finding",
            {"title": "x", "severity": "low"}, user_id=_s["viewer"],
        )
        assert "error" in result
        assert "findings.create" in result["error"]

    @pytest.mark.asyncio
    async def test_auditor_denied(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "create_finding",
            {"title": "x", "severity": "low"}, user_id=_s["auditor"],
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_editor_allowed(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "create_finding",
            {"title": "editor finding", "severity": "low"}, user_id=_s["editor"],
        )
        assert "error" not in result
        assert result["title"] == "editor finding"


class TestAddHostTagPermission:
    """add_host_tag is RiskLevel.WRITE, required_permission="hosts.update"."""

    @pytest.mark.asyncio
    async def test_viewer_denied(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "add_host_tag",
            {"host_id": _s["host_id"], "tag": "should-not-apply"}, user_id=_s["viewer"],
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_operator_allowed(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "add_host_tag",
            {"host_id": _s["host_id"], "tag": "operator-applied"}, user_id=_s["operator"],
        )
        assert "error" not in result
        assert "operator-applied" in result["tags"]


class TestRunPlaybookPermission:
    """run_playbook is RiskLevel.CRITICAL, required_permission="command_outputs.create"."""

    @pytest.mark.asyncio
    async def test_viewer_denied(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "run_playbook",
            {"playbook_id": "does-not-exist"}, user_id=_s["viewer"],
        )
        assert "error" in result
        assert "command_outputs.create" in result["error"]

    @pytest.mark.asyncio
    async def test_auditor_denied(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "run_playbook",
            {"playbook_id": "does-not-exist"}, user_id=_s["auditor"],
        )
        assert "error" in result
        assert "command_outputs.create" in result["error"]


class TestReadToolPermissions:
    """Read tools now require the exact same permission as their REST GET
    equivalent — "findings.read" on the chat endpoint only proves project
    membership, not that this role can read *this* resource. reviewer has
    findings.read (can open the chat) but not hosts.read/credentials.read/
    command_outputs.read on the direct REST routes; auditor has hosts.read
    and command_outputs.read but not credentials.read. Both gaps must carry
    over to chat exactly as they exist on the REST routes."""

    @pytest.mark.asyncio
    async def test_reviewer_denied_list_hosts(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "list_hosts", {}, user_id=_s["reviewer"],
        )
        assert "error" in result
        assert "hosts.read" in result["error"]

    @pytest.mark.asyncio
    async def test_reviewer_denied_get_host(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "get_host", {"host_id": _s["host_id"]}, user_id=_s["reviewer"],
        )
        assert "error" in result
        assert "hosts.read" in result["error"]

    @pytest.mark.asyncio
    async def test_auditor_denied_list_creds(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "list_creds", {}, user_id=_s["auditor"],
        )
        assert "error" in result
        assert "credentials.read" in result["error"]

    @pytest.mark.asyncio
    async def test_reviewer_denied_list_jobs(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "list_jobs", {}, user_id=_s["reviewer"],
        )
        assert "error" in result
        assert "command_outputs.read" in result["error"]

    @pytest.mark.asyncio
    async def test_reviewer_denied_list_activities(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "list_activities", {}, user_id=_s["reviewer"],
        )
        assert "error" in result
        assert "command_outputs.read" in result["error"]

    @pytest.mark.asyncio
    async def test_reviewer_allowed_get_scope(self, module_db):
        # reviewer has scopes.read even though it lacks hosts/creds/jobs
        # read — confirms this is per-resource, not a blanket chat block.
        result = await tool_registry.execute(
            module_db, _s["pid"], "get_scope", {}, user_id=_s["reviewer"],
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_auditor_allowed_list_hosts_and_jobs(self, module_db):
        # auditor has hosts.read/command_outputs.read, just not
        # credentials.read — the earlier list_creds denial is specific.
        assert isinstance(
            await tool_registry.execute(module_db, _s["pid"], "list_hosts", {}, user_id=_s["auditor"]),
            list,
        )
        assert isinstance(
            await tool_registry.execute(module_db, _s["pid"], "list_jobs", {}, user_id=_s["auditor"]),
            list,
        )

    @pytest.mark.asyncio
    async def test_viewer_allowed_everything_read(self, module_db):
        # viewer holds every read permission the new mapping checks.
        for name, args in [
            ("list_hosts", {}), ("list_creds", {}), ("list_findings", {}),
            ("list_jobs", {}), ("list_activities", {}), ("get_scope", {}),
        ]:
            result = await tool_registry.execute(module_db, _s["pid"], name, args, user_id=_s["viewer"])
            assert isinstance(result, list), f"{name}: {result}"

    @pytest.mark.asyncio
    async def test_cross_project_briefing_has_no_required_permission(self, module_db):
        # Deliberately unmapped: it iterates every project
        # get_user_member_pids() returns for the caller instead of
        # reading `pid`, so there's no single project permission to check.
        assert tool_registry.get("cross_project_briefing").required_permission is None
        result = await tool_registry.execute(
            module_db, _s["pid"], "cross_project_briefing", {}, user_id=_s["reviewer"],
        )
        assert "error" not in result


class TestAutomationPathUnaffected:
    """No user_id (the automations executor's call shape) skips the permission
    check entirely — an automation was already authorized at creation/trigger
    time against its creator's role, and there's no live actor to re-check."""

    @pytest.mark.asyncio
    async def test_create_finding_without_user_id_still_works(self, module_db):
        result = await tool_registry.execute(
            module_db, _s["pid"], "create_finding",
            {"title": "automation finding", "severity": "medium"}, user_id=None,
        )
        assert "error" not in result
        assert result["title"] == "automation finding"
