from __future__ import annotations

import importlib.util
import os
import shutil
import tomllib
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from .. import models
from ..core.logging_setup import get_logger
from ..core.plugin_signing import require_signature, verify_signature
from ..core.utils import ts_now
from .registry import registry
from .types import BackendModule

logger = get_logger(__name__)

DATA_PLUGINS_DIR = Path(os.environ.get("UPLOAD_ROOT", "/tmp/umbryx")) / "plugins"

VALID_PERMISSION_KEYS = {"hosts", "creds", "findings", "scopes", "loot", "jobs", "hosts_activity"}
VALID_PERMISSION_MODES = {"read", "write", "exec"}
VALID_CATEGORIES = {"scan", "execution", "c2", "infra", "dns", "notify", "topology"}
CURRENT_API_VERSION = 1


class PluginError(Exception):
    pass


class PluginManifest:
    def __init__(self, data: dict):
        plugin = data.get("plugin", {})
        self.id: str = plugin.get("id", "")
        self.version: str = plugin.get("version", "0.0.0")
        self.api_version: int = plugin.get("api_version", 1)
        self.title: str = plugin.get("title", self.id)
        self.description: str = plugin.get("description", "")
        self.author: str = plugin.get("author", "")
        self.license: str = plugin.get("license", "")
        self.homepage: str = plugin.get("homepage", "")
        self.min_platform: str = plugin.get("min_platform", "")
        self.permissions: dict = data.get("permissions", {})
        self.extensions: dict = data.get("extensions", {})
        self.raw: dict = data

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.id or not self.id.replace("-", "").replace("_", "").isalnum():
            errors.append("plugin.id must be non-empty alphanumeric (dashes/underscores ok)")
        if not self.version:
            errors.append("plugin.version is required")
        if self.api_version < 1 or self.api_version > CURRENT_API_VERSION:
            errors.append(
                f"plugin.api_version must be 1..{CURRENT_API_VERSION}, got {self.api_version}"
            )
        for mode, keys in self.permissions.items():
            if mode not in VALID_PERMISSION_MODES:
                errors.append(f"Unknown permission mode: {mode}")
            else:
                unknown = set(keys) - VALID_PERMISSION_KEYS
                if unknown:
                    errors.append(f"Unknown permission keys in {mode}: {unknown}")
        return errors


def _parse_manifest(toml_bytes: bytes) -> PluginManifest:
    try:
        data = tomllib.loads(toml_bytes.decode("utf-8"))
    except Exception as e:
        raise PluginError(f"Invalid plugin.toml: {e}")
    manifest = PluginManifest(data)
    errors = manifest.validate()
    if errors:
        raise PluginError(f"Manifest validation failed: {'; '.join(errors)}")
    return manifest


def install_plugin(
    bundle_path: Path, db: Session, user_id: str | None = None, signature: str | None = None
) -> models.InstalledPlugin:
    if not zipfile.is_zipfile(bundle_path):
        raise PluginError("Bundle must be a zip archive")

    if require_signature() and not signature:
        raise PluginError("Plugin signature required (PLUGIN_REQUIRE_SIGNATURE=true)")

    content = bundle_path.read_bytes()
    if signature and not verify_signature(content, signature):
        raise PluginError("Invalid plugin signature")

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = zf.namelist()
        if "plugin.toml" not in names:
            raise PluginError("Bundle missing plugin.toml manifest")
        manifest = _parse_manifest(zf.read("plugin.toml"))

        existing = (
            db.query(models.InstalledPlugin)
            .filter(models.InstalledPlugin.id == manifest.id)
            .first()
        )
        if existing and existing.source == "builtin":
            raise PluginError(f"Cannot overwrite builtin plugin: {manifest.id}")

        extract_dir = DATA_PLUGINS_DIR / manifest.id
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)
        zf.extractall(extract_dir)

    frontend_js = extract_dir / "frontend" / "index.js"
    has_frontend = frontend_js.exists()
    if has_frontend:
        serve_dir = DATA_PLUGINS_DIR / "_serve" / manifest.id
        serve_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(frontend_js, serve_dir / "frontend.js")

    plugin = existing
    if plugin:
        plugin.version = manifest.version
        plugin.api_version = manifest.api_version
        plugin.bundle_path = str(extract_dir)
        plugin.manifest = manifest.raw
        plugin.permissions = manifest.permissions
        plugin.signature = signature
        plugin.error = None
    else:
        plugin = models.InstalledPlugin(
            id=manifest.id,
            version=manifest.version,
            api_version=manifest.api_version,
            source="uploaded",
            enabled=True,
            bundle_path=str(extract_dir),
            manifest=manifest.raw,
            permissions=manifest.permissions,
            installed_at=ts_now(),
            installed_by=user_id,
            signature=signature,
        )
        db.add(plugin)

    db.commit()
    db.refresh(plugin)

    _load_backend_module(manifest, extract_dir)

    logger.info(
        "Plugin installed: %s v%s (api=%d, frontend=%s)",
        manifest.id,
        manifest.version,
        manifest.api_version,
        has_frontend,
    )
    return plugin


def _load_backend_module(manifest: PluginManifest, extract_dir: Path) -> BackendModule | None:
    backend_init = extract_dir / "backend" / "main.py"
    if not backend_init.exists():
        return None

    try:
        spec = importlib.util.spec_from_file_location(
            f"plugin_{manifest.id}",
            str(backend_init),
            submodule_search_locations=[str(extract_dir / "backend")],
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:
        logger.error("Failed to load backend for plugin %s: %s", manifest.id, e)
        return None

    connectors = []
    if hasattr(mod, "CONNECTORS"):
        from ..core.connectors import ToolConnector

        for c in mod.CONNECTORS:
            if isinstance(c, ToolConnector):
                connectors.append(c)

    scan_parsers = {}
    if hasattr(mod, "SCAN_PARSERS"):
        scan_parsers = dict(mod.SCAN_PARSERS)

    module = BackendModule(
        name=manifest.id,
        version=manifest.version,
        title=manifest.title,
        description=manifest.description,
        enabled=True,
        source="uploaded",
        editable=True,
        connectors=connectors,
        scan_parsers=scan_parsers,
    )
    registry.register(module)
    return module


def uninstall_plugin(plugin_id: str, db: Session) -> bool:
    plugin = db.query(models.InstalledPlugin).filter(models.InstalledPlugin.id == plugin_id).first()
    if not plugin:
        return False
    if plugin.source == "builtin":
        raise PluginError("Cannot uninstall builtin plugin")

    extract_dir = Path(plugin.bundle_path) if plugin.bundle_path else DATA_PLUGINS_DIR / plugin_id
    if extract_dir.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)

    serve_dir = DATA_PLUGINS_DIR / "_serve" / plugin_id
    if serve_dir.exists():
        shutil.rmtree(serve_dir, ignore_errors=True)

    registry._modules.pop(plugin_id, None)
    db.delete(plugin)
    db.commit()
    logger.info("Plugin uninstalled: %s", plugin_id)
    return True


def get_plugin_frontend_js(plugin_id: str) -> str | None:
    serve_path = DATA_PLUGINS_DIR / "_serve" / plugin_id / "frontend.js"
    if serve_path.exists():
        return serve_path.read_text(encoding="utf-8")
    return None


def list_installed_plugins(db: Session) -> list[dict]:
    rows = db.query(models.InstalledPlugin).order_by(models.InstalledPlugin.installed_at).all()
    result = []
    for row in rows:
        d = {
            "id": row.id,
            "version": row.version,
            "api_version": row.api_version,
            "source": row.source,
            "enabled": row.enabled,
            "title": row.manifest.get("plugin", {}).get("title", row.id),
            "description": row.manifest.get("plugin", {}).get("description", ""),
            "permissions": row.permissions,
            "installed_at": row.installed_at,
            "installed_by": row.installed_by,
            "has_frontend": (DATA_PLUGINS_DIR / "_serve" / row.id / "frontend.js").exists(),
            "error": row.error,
        }
        result.append(d)
    return result


def toggle_plugin(plugin_id: str, enabled: bool, db: Session) -> models.InstalledPlugin | None:
    plugin = db.query(models.InstalledPlugin).filter(models.InstalledPlugin.id == plugin_id).first()
    if not plugin:
        return None
    plugin.enabled = enabled
    db.commit()
    db.refresh(plugin)

    mod = registry.get(plugin_id)
    if mod:
        mod.enabled = enabled

    return plugin
