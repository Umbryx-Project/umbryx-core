"""Builtin KB seeds + automation templates (2026-09-24)."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.kb_seed import KB_GUIDES, KB_GUIDES_CATEGORY, KB_PLATFORM_CATEGORY


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


class TestKBKnowledgeSeed:
    def test_seed_endpoint_creates_and_is_idempotent(self, module_client: TestClient, module_db: Session):
        from app import models

        _admin(module_client)
        r = module_client.post("/api/kb/seed/knowledge")
        assert r.status_code == 200, r.text
        first = r.json()
        assert first["created"] == len(KB_GUIDES) > 15

        # rows exist, global, both categories present, marker tags
        rows = (
            module_db.query(models.KBArticle)
            .filter(models.KBArticle.pid.is_(None))
            .all()
        )
        cats = {a.category for a in rows}
        assert KB_GUIDES_CATEGORY in cats and KB_PLATFORM_CATEGORY in cats
        markers = {a.tags[0] for a in rows if a.tags}
        assert f"kb:builtin:attacker-ssh" in markers

        # re-run is a no-op
        r2 = module_client.post("/api/kb/seed/knowledge")
        assert r2.json()["created"] == 0
        assert r2.json()["skipped"] == len(KB_GUIDES)

    def test_guides_visible_in_kb_listing(self, module_client: TestClient):
        _admin(module_client)
        r = module_client.get("/api/kb")
        assert r.status_code == 200
        titles = {a["title"] for a in r.json()}
        assert any("Smart Build" in t for t in titles)

    def test_requires_admin(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        r = module_client.post("/api/kb/seed/knowledge")
        assert r.status_code in (401, 403)

    def test_all_guides_have_content(self):
        for slug, title, category, tags, content in KB_GUIDES:
            assert len(content) > 200, slug
            assert category in (KB_GUIDES_CATEGORY, KB_PLATFORM_CATEGORY)
            assert tags and all(t for t in tags)


class TestAutomationTemplates:
    def test_all_builtin_templates_validate(self, module_client: TestClient, module_db: Session):
        from app.core.automations.definition import parse_definition
        from app.core.automations.validator import validate_definition
        from app.core.ai.tool_registry import tool_registry
        from app.routers.automations_api import _BUILTIN_TEMPLATES

        _admin(module_client)
        assert len(_BUILTIN_TEMPLATES) >= 9  # 3 original + 6+ new
        tools = set(tool_registry.list_names())
        for tpl in _BUILTIN_TEMPLATES:
            defn = parse_definition(tpl["definition"])
            result = validate_definition(defn, tools, set())
            assert result.ok, f"{tpl['name']}: {[e.message for e in result.errors]}"

    def test_templates_endpoint_lists_new_ones(self, module_client: TestClient, module_db: Session):
        from tests.test_workstation_pool import ADMIN_PASS

        _admin(module_client)
        module_client.post("/api/projects", json={"name": "Tpl test", "added": "2026-09-24T00:00:00Z", "status": "active"})
        pid = module_client.get("/api/projects").json()[-1]["id"]
        r = module_client.get(f"/api/projects/{pid}/automations/templates")
        assert r.status_code == 200, r.text
        names = {t["name"] for t in r.json()["templates"]}
        assert "Failed Job Watchdog" in names
        assert "Triage Queue: New Hosts" in names
        assert "Weekly Findings Digest" in names
