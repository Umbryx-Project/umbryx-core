"""
Extension manifest — declarative module descriptor.

A manifest is a YAML file (`manifest.yaml`) that declares what a module
provides: object types, extension points, routes, settings, permissions.

The manifest is the *single source of truth* for a module's capabilities.
Backend code (Python) and frontend code (JSX) are discovered relative to
the manifest location.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MANIFEST_FILENAME = "manifest.yaml"

MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[\w.]+)?$")

KNOWN_EXTENSION_POINTS = frozenset(
    {
        "sidebar.nav",
        "project.tab",
        "host.tab",
        "network.tab",
        "dashboard.widget",
        "settings.section",
        "report.section",
        "actions.host",
        "actions.finding",
        "actions.cred",
        "actions.object",
        "importer",
        "search.provider",
    }
)

VALID_FIELD_TYPES = frozenset(
    {
        "string",
        "text",
        "integer",
        "float",
        "boolean",
        "enum",
        "datetime",
        "json",
        "reference",
    }
)

VALID_PERMISSION_SCOPES = frozenset(
    {
        "hosts",
        "creds",
        "findings",
        "scopes",
        "loot",
        "jobs",
        "notes",
        "networks",
        "tasks",
        "object",  # universal object model
        "settings",
    }
)

VALID_PERMISSION_MODES = frozenset({"read", "write", "exec"})


class ManifestError(ValueError):
    """Raised when a manifest fails validation."""


@dataclass
class ObjectFieldSchema:
    name: str
    type: str
    label: str = ""
    required: bool = False
    default: Any = None
    options: list[str] | None = None
    reference_type: str | None = None
    placeholder: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> ObjectFieldSchema:
        ftype = data.get("type", "string")
        if ftype not in VALID_FIELD_TYPES:
            raise ManifestError(
                f"Field '{data.get('name')}': invalid type '{ftype}'. "
                f"Must be one of {sorted(VALID_FIELD_TYPES)}"
            )
        return cls(
            name=data["name"],
            type=ftype,
            label=data.get("label", data["name"].replace("_", " ").title()),
            required=data.get("required", False),
            default=data.get("default"),
            options=data.get("options"),
            reference_type=data.get("reference_type"),
            placeholder=data.get("placeholder", ""),
        )

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "label": self.label,
            "required": self.required,
        }
        if self.default is not None:
            d["default"] = self.default
        if self.options:
            d["options"] = self.options
        if self.reference_type:
            d["reference_type"] = self.reference_type
        if self.placeholder:
            d["placeholder"] = self.placeholder
        return d


@dataclass
class ObjectTypeSchema:
    type: str
    name: str
    icon: str = ""
    fields: list[ObjectFieldSchema] = field(default_factory=list)
    list_columns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> ObjectTypeSchema:
        fields = [ObjectFieldSchema.from_dict(f) for f in data.get("fields", [])]
        return cls(
            type=data["type"],
            name=data.get("name", data["type"].replace("_", " ").title()),
            icon=data.get("icon", ""),
            fields=fields,
            list_columns=data.get("list_columns", []),
        )

    @property
    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]

    def field_by_name(self, name: str) -> ObjectFieldSchema | None:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "name": self.name,
            "icon": self.icon,
            "fields": [f.to_dict() for f in self.fields],
            "list_columns": self.list_columns,
        }


@dataclass
class ExtensionPointEntry:
    """A single registration into an extension point."""

    point: str
    data: dict

    def to_dict(self) -> dict:
        return {"point": self.point, **self.data}


@dataclass
class SettingSchema:
    key: str
    label: str
    type: str
    default: Any = None
    options: list[str] | None = None
    description: str = ""
    placeholder: str = ""

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "type": self.type,
        }
        if self.default is not None:
            d["default"] = self.default
        if self.options:
            d["options"] = self.options
        if self.description:
            d["description"] = self.description
        if self.placeholder:
            d["placeholder"] = self.placeholder
        return d


@dataclass
class Manifest:
    """Parsed and validated module manifest."""

    id: str
    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = ""
    icon: str = ""

    depends_on: list[str] = field(default_factory=list)
    conflicts_with: list[str] = field(default_factory=list)

    permissions: list[str] = field(default_factory=list)

    objects: list[ObjectTypeSchema] = field(default_factory=list)
    extensions: list[ExtensionPointEntry] = field(default_factory=list)
    settings: list[SettingSchema] = field(default_factory=list)

    route_prefix: str = ""
    backend_entry: str = ""

    source_path: Path | None = None

    # ── Parsing ────────────────────────────────────────────────────────

    @classmethod
    def parse(cls, yaml_text: str, source_path: Path | None = None) -> Manifest:
        data = yaml.safe_load(yaml_text)
        if not isinstance(data, dict):
            raise ManifestError("Manifest must be a YAML mapping")
        return cls.from_dict(data, source_path)

    @classmethod
    def from_file(cls, path: Path) -> Manifest:
        return cls.parse(path.read_text(encoding="utf-8"), source_path=path.parent)

    @classmethod
    def from_dict(cls, data: dict, source_path: Path | None = None) -> Manifest:
        mid = data.get("id", "")
        if not MODULE_ID_RE.match(mid):
            raise ManifestError(f"Invalid module id '{mid}'. Must match {MODULE_ID_RE.pattern}")

        version = data.get("version", "")
        if not SEMVER_RE.match(version):
            raise ManifestError(f"Invalid version '{version}'. Must be semver (e.g. 1.0.0)")

        permissions = data.get("permissions", [])
        cls._validate_permissions(permissions, mid)

        objects = [ObjectTypeSchema.from_dict(o) for o in data.get("objects", [])]

        extensions_raw = data.get("extensions", {})
        extensions = cls._parse_extensions(extensions_raw, mid)

        settings = [
            SettingSchema(
                key=s["key"],
                label=s.get("label", s["key"]),
                type=s.get("type", "string"),
                default=s.get("default"),
                options=s.get("options"),
                description=s.get("description", ""),
                placeholder=s.get("placeholder", ""),
            )
            for s in data.get("settings", [])
        ]

        return cls(
            id=mid,
            name=data.get("name", mid),
            version=version,
            description=data.get("description", ""),
            author=data.get("author", ""),
            license=data.get("license", ""),
            icon=data.get("icon", ""),
            depends_on=data.get("depends_on", []),
            conflicts_with=data.get("conflicts_with", []),
            permissions=permissions,
            objects=objects,
            extensions=extensions,
            settings=settings,
            route_prefix=data.get("route_prefix", f"/api/ext/{mid}"),
            backend_entry=data.get("backend_entry", ""),
            source_path=source_path,
        )

    # ── Validation helpers ─────────────────────────────────────────────

    @staticmethod
    def _validate_permissions(permissions: list[str], module_id: str) -> None:
        for perm in permissions:
            if ":" not in perm:
                raise ManifestError(
                    f"[{module_id}] Invalid permission '{perm}'. "
                    f"Must be 'mode:scope' (e.g. 'read:hosts')"
                )
            mode, scope = perm.split(":", 1)
            if mode not in VALID_PERMISSION_MODES:
                raise ManifestError(
                    f"[{module_id}] Invalid permission mode '{mode}'. "
                    f"Must be one of {sorted(VALID_PERMISSION_MODES)}"
                )
            if scope not in VALID_PERMISSION_SCOPES:
                raise ManifestError(
                    f"[{module_id}] Invalid permission scope '{scope}'. "
                    f"Must be one of {sorted(VALID_PERMISSION_SCOPES)}"
                )

    @staticmethod
    def _parse_extensions(extensions_raw: dict, module_id: str) -> list[ExtensionPointEntry]:
        if not isinstance(extensions_raw, dict):
            raise ManifestError(f"[{module_id}] 'extensions' must be a mapping")
        result: list[ExtensionPointEntry] = []
        for point, entries in extensions_raw.items():
            if point not in KNOWN_EXTENSION_POINTS:
                raise ManifestError(
                    f"[{module_id}] Unknown extension point '{point}'. "
                    f"Known: {sorted(KNOWN_EXTENSION_POINTS)}"
                )
            if not isinstance(entries, list):
                entries = [entries]
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ManifestError(
                        f"[{module_id}] Extension entry in '{point}' must be a mapping"
                    )
                result.append(ExtensionPointEntry(point=point, data=entry))
        return result

    # ── Accessors ──────────────────────────────────────────────────────

    @property
    def object_types(self) -> dict[str, ObjectTypeSchema]:
        return {o.type: o for o in self.objects}

    def extensions_for(self, point: str) -> list[dict]:
        return [e.data for e in self.extensions if e.point == point]

    @property
    def settings_defaults(self) -> dict[str, Any]:
        return {s.key: s.default for s in self.settings if s.default is not None}

    # ── Serialization ──────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "icon": self.icon,
            "depends_on": self.depends_on,
            "conflicts_with": self.conflicts_with,
            "permissions": self.permissions,
            "objects": [o.to_dict() for o in self.objects],
            "extensions": [e.to_dict() for e in self.extensions],
            "settings": [s.to_dict() for s in self.settings],
            "route_prefix": self.route_prefix,
            "source": "extension",
        }
