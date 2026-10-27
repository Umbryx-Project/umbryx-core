"""
Unit tests for the Umbryx module framework.

Tests manifest parsing/validation, extension point registry,
object type registry, module loader, and lifecycle.
"""

import tempfile
from pathlib import Path

import pytest

from app.core.modules.manifest import (
    Manifest,
    ManifestError,
    ObjectFieldSchema,
    ObjectTypeSchema,
    KNOWN_EXTENSION_POINTS,
)
from app.core.modules.extension_points import ExtensionPointRegistry
from app.core.modules.object_types import ObjectTypeRegistry
from app.core.modules.loader import ModuleLoader, validate_module_set
from app.core.modules.validator import validate_module
from app.core.modules.lifecycle import enable_module, disable_module, health_check


# ── Manifest parsing ────────────────────────────────────────────────────


class TestManifestParsing:
    def test_valid_manifest(self):
        m = Manifest.parse("""
id: test-module
name: Test Module
version: 1.0.0
description: A test module
""")
        assert m.id == "test-module"
        assert m.name == "Test Module"
        assert m.version == "1.0.0"

    def test_invalid_id_rejected(self):
        with pytest.raises(ManifestError, match="Invalid module id"):
            Manifest.parse("""
id: Invalid_ID!
name: Bad
version: 1.0.0
""")

    def test_invalid_version_rejected(self):
        with pytest.raises(ManifestError, match="Invalid version"):
            Manifest.parse("""
id: test
name: Test
version: not-semver
""")

    def test_uppercase_id_rejected(self):
        with pytest.raises(ManifestError):
            Manifest.parse("id: TestModule\nname: Test\nversion: 1.0.0\n")

    def test_permissions_validated(self):
        with pytest.raises(ManifestError, match="Invalid permission"):
            Manifest.parse("""
id: test
name: Test
version: 1.0.0
permissions:
  - hack:everything
""")

    def test_valid_permissions(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
permissions:
  - read:hosts
  - write:findings
  - exec:jobs
""")
        assert len(m.permissions) == 3

    def test_objects_parsed(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
objects:
  - type: widget
    name: Widget
    fields:
      - name: title
        type: string
        required: true
      - name: count
        type: integer
        default: 0
      - name: priority
        type: enum
        options: [low, high]
""")
        assert len(m.objects) == 1
        obj = m.objects[0]
        assert obj.type == "widget"
        assert len(obj.fields) == 3
        assert obj.fields[0].required is True
        assert obj.fields[2].options == ["low", "high"]

    def test_extensions_parsed(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
extensions:
  sidebar.nav:
    - id: my-view
      label: My View
  dashboard.widget:
    - id: my-widget
      label: Widget
""")
        assert len(m.extensions) == 2
        nav = m.extensions_for("sidebar.nav")
        assert len(nav) == 1
        assert nav[0]["id"] == "my-view"

    def test_unknown_extension_point_rejected(self):
        with pytest.raises(ManifestError, match="Unknown extension point"):
            Manifest.parse("""
id: test
name: Test
version: 1.0.0
extensions:
  bogus.point:
    - id: x
""")

    def test_from_file(self, tmp_path):
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text("""
id: file-test
name: File Test
version: 2.1.0
""")
        m = Manifest.from_file(manifest_file)
        assert m.id == "file-test"
        assert m.source_path == tmp_path

    def test_settings_parsed(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
settings:
  - key: max_items
    label: Max Items
    type: integer
    default: 50
""")
        assert len(m.settings) == 1
        assert m.settings[0].key == "max_items"
        assert m.settings_defaults == {"max_items": 50}

    def test_to_dict_roundtrip(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
description: Test module
objects:
  - type: item
    name: Item
    fields:
      - name: title
        type: string
""")
        d = m.to_dict()
        assert d["id"] == "test"
        assert d["source"] == "extension"
        assert len(d["objects"]) == 1


# ── Extension point registry ────────────────────────────────────────────


class TestExtensionPointRegistry:
    def test_register_and_get(self):
        reg = ExtensionPointRegistry()
        reg.register("mod1", "sidebar.nav", {"id": "view1", "label": "View 1"})
        entries = reg.get("sidebar.nav")
        assert len(entries) == 1
        assert entries[0].data["id"] == "view1"
        assert entries[0].module_id == "mod1"

    def test_unregister_module(self):
        reg = ExtensionPointRegistry()
        reg.register("mod1", "sidebar.nav", {"id": "v1"})
        reg.register("mod2", "sidebar.nav", {"id": "v2"})
        reg.unregister_module("mod1")
        entries = reg.get("sidebar.nav")
        assert len(entries) == 1
        assert entries[0].module_id == "mod2"

    def test_get_dicts(self):
        reg = ExtensionPointRegistry()
        reg.register("mod1", "dashboard.widget", {"id": "w1", "label": "W1"})
        dicts = reg.get_dicts("dashboard.widget")
        assert dicts[0]["id"] == "w1"
        assert dicts[0]["module_id"] == "mod1"

    def test_all_points(self):
        reg = ExtensionPointRegistry()
        reg.register("mod1", "sidebar.nav", {"id": "v1"})
        reg.register("mod1", "dashboard.widget", {"id": "w1"})
        all_p = reg.all_points()
        assert "sidebar.nav" in all_p
        assert "dashboard.widget" in all_p

    def test_get_for_module(self):
        reg = ExtensionPointRegistry()
        reg.register("mod1", "sidebar.nav", {"id": "v1"})
        reg.register("mod1", "dashboard.widget", {"id": "w1"})
        reg.register("mod2", "sidebar.nav", {"id": "v2"})
        mod1_entries = reg.get_for_module("mod1")
        assert len(mod1_entries) == 2


# ── Object type registry ────────────────────────────────────────────────


class TestObjectTypeRegistry:
    def _make_schema(self):
        return ObjectTypeSchema(
            type="vulnerability",
            name="Vulnerability",
            fields=[
                ObjectFieldSchema(name="title", type="string", label="Title", required=True),
                ObjectFieldSchema(name="severity", type="enum", label="Severity",
                                  options=["low", "medium", "high"]),
                ObjectFieldSchema(name="score", type="float", label="Score"),
            ],
        )

    def test_register_and_get(self):
        reg = ObjectTypeRegistry()
        schema = self._make_schema()
        reg.register("sec-module", schema)
        assert reg.get("vulnerability") is not None
        assert reg.get_module("vulnerability") == "sec-module"

    def test_duplicate_type_rejected(self):
        reg = ObjectTypeRegistry()
        schema = self._make_schema()
        reg.register("mod1", schema)
        with pytest.raises(ValueError, match="already registered"):
            reg.register("mod2", schema)

    def test_same_module_re_register_ok(self):
        reg = ObjectTypeRegistry()
        schema = self._make_schema()
        reg.register("mod1", schema)
        reg.register("mod1", schema)  # should not raise

    def test_unregister_module(self):
        reg = ObjectTypeRegistry()
        reg.register("mod1", self._make_schema())
        reg.unregister_module("mod1")
        assert reg.get("vulnerability") is None

    def test_validate_data_valid(self):
        reg = ObjectTypeRegistry()
        reg.register("mod1", self._make_schema())
        errors = reg.validate_data("vulnerability", {
            "title": "XSS in login",
            "severity": "high",
            "score": 8.5,
        })
        assert errors == []

    def test_validate_data_missing_required(self):
        reg = ObjectTypeRegistry()
        reg.register("mod1", self._make_schema())
        errors = reg.validate_data("vulnerability", {"severity": "high"})
        assert any("title" in e for e in errors)

    def test_validate_data_invalid_enum(self):
        reg = ObjectTypeRegistry()
        reg.register("mod1", self._make_schema())
        errors = reg.validate_data("vulnerability", {
            "title": "Test",
            "severity": "catastrophic",
        })
        assert any("severity" in e for e in errors)

    def test_validate_data_wrong_type(self):
        reg = ObjectTypeRegistry()
        reg.register("mod1", self._make_schema())
        errors = reg.validate_data("vulnerability", {
            "title": "Test",
            "score": "not a number",
        })
        assert any("score" in e for e in errors)

    def test_validate_data_unknown_type(self):
        reg = ObjectTypeRegistry()
        errors = reg.validate_data("nonexistent", {"foo": "bar"})
        assert any("Unknown object type" in e for e in errors)


# ── Validator ───────────────────────────────────────────────────────────


class TestValidator:
    def test_valid_manifest_no_errors(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
objects:
  - type: item
    name: Item
    list_columns: [title]
    fields:
      - name: title
        type: string
      - name: priority
        type: enum
        options: [a, b]
""")
        errors = validate_module(m)
        assert errors == []

    def test_duplicate_field_detected(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
objects:
  - type: item
    name: Item
    fields:
      - name: title
        type: string
      - name: title
        type: string
""")
        errors = validate_module(m)
        assert any("duplicate field" in e for e in errors)

    def test_list_column_not_in_fields(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
objects:
  - type: item
    name: Item
    list_columns: [nonexistent]
    fields:
      - name: title
        type: string
""")
        errors = validate_module(m)
        assert any("list_column" in e for e in errors)

    def test_enum_without_options(self):
        m = Manifest.parse("""
id: test
name: Test
version: 1.0.0
objects:
  - type: item
    name: Item
    fields:
      - name: level
        type: enum
""")
        errors = validate_module(m)
        assert any("enum but has no options" in e for e in errors)


# ── Dependency validation ──────────────────────────────────────────────


class TestDependencyValidation:
    def test_missing_dependency(self):
        m1 = Manifest.parse("id: mod-a\nname: A\nversion: 1.0.0\ndepends_on: [mod-b]\n")
        errors = validate_module_set({"mod-a": m1})
        assert "mod-a" in errors
        assert any("mod-b" in e for e in errors["mod-a"])

    def test_satisfied_dependency(self):
        m1 = Manifest.parse("id: mod-a\nname: A\nversion: 1.0.0\ndepends_on: [mod-b]\n")
        m2 = Manifest.parse("id: mod-b\nname: B\nversion: 1.0.0\n")
        errors = validate_module_set({"mod-a": m1, "mod-b": m2})
        assert errors == {}

    def test_conflict_detected(self):
        m1 = Manifest.parse("id: mod-a\nname: A\nversion: 1.0.0\nconflicts_with: [mod-b]\n")
        m2 = Manifest.parse("id: mod-b\nname: B\nversion: 1.0.0\n")
        errors = validate_module_set({"mod-a": m1, "mod-b": m2})
        assert "mod-a" in errors

    def test_circular_dependency(self):
        m1 = Manifest.parse("id: mod-a\nname: A\nversion: 1.0.0\ndepends_on: [mod-b]\n")
        m2 = Manifest.parse("id: mod-b\nname: B\nversion: 1.0.0\ndepends_on: [mod-a]\n")
        errors = validate_module_set({"mod-a": m1, "mod-b": m2})
        assert "mod-a" in errors
        assert any("Circular" in e for e in errors["mod-a"])


# ── Module loader ───────────────────────────────────────────────────────


class TestModuleLoader:
    def test_discover_empty_dir(self, tmp_path):
        loader = ModuleLoader(tmp_path)
        assert loader.discover() == []

    def test_load_valid_module(self, tmp_path):
        mod_dir = tmp_path / "test-mod"
        mod_dir.mkdir()
        (mod_dir / "manifest.yaml").write_text("""
id: test-mod
name: Test Module
version: 1.0.0
""")
        loader = ModuleLoader(tmp_path)
        loaded = loader.load_all()
        assert len(loaded) == 1
        assert loaded[0].id == "test-mod"
        assert loaded[0].enabled is True

    def test_load_invalid_manifest(self, tmp_path):
        mod_dir = tmp_path / "bad-mod"
        mod_dir.mkdir()
        (mod_dir / "manifest.yaml").write_text("id: BAD!\nname: Bad\nversion: nope\n")
        loader = ModuleLoader(tmp_path)
        loaded = loader.load_all()
        assert len(loaded) == 1
        assert loaded[0].enabled is False
        assert loaded[0].error is not None

    def test_get_by_id(self, tmp_path):
        mod_dir = tmp_path / "my-mod"
        mod_dir.mkdir()
        (mod_dir / "manifest.yaml").write_text("id: my-mod\nname: My\nversion: 1.0.0\n")
        loader = ModuleLoader(tmp_path)
        loader.load_all()
        lm = loader.get("my-mod")
        assert lm is not None
        assert lm.id == "my-mod"

    def test_backend_router_loaded(self, tmp_path):
        mod_dir = tmp_path / "router-mod"
        backend_dir = mod_dir / "backend"
        backend_dir.mkdir(parents=True)
        (mod_dir / "manifest.yaml").write_text("""
id: router-mod
name: Router
version: 1.0.0
backend_entry: routes
""")
        (backend_dir / "routes.py").write_text("""
from fastapi import APIRouter
router = APIRouter()

@router.get("/test")
def test():
    return {"ok": True}

FASTAPI_ROUTER = router
""")
        loader = ModuleLoader(tmp_path)
        loaded = loader.load_all()
        assert len(loaded) == 1
        lm = loaded[0]
        assert lm._router is not None

    def test_load_multiple_modules(self, tmp_path):
        for i in range(3):
            mod_dir = tmp_path / f"mod-{i}"
            mod_dir.mkdir()
            (mod_dir / "manifest.yaml").write_text(
                f"id: mod-{i}\nname: Mod {i}\nversion: 1.0.0\n"
            )
        loader = ModuleLoader(tmp_path)
        loaded = loader.load_all()
        assert len(loaded) == 3
