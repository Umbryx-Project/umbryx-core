"""
Module loader — discovers and loads modules from the filesystem.

At startup, scans the ``/modules/`` directory for ``manifest.yaml`` files.
Each discovered module is:

1. Parsed and validated (manifest.py)
2. Checked for dependency satisfaction and conflicts (validator.py)
3. Registered in the extension point and object type registries
4. Its backend entry point (if any) imported to register routes/hooks

Modules can also be loaded at runtime via ``load_module(path)``.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

from ..logging_setup import get_logger
from .manifest import MANIFEST_FILENAME, Manifest, ManifestError

logger = get_logger(__name__)

DEFAULT_MODULES_DIR = Path(os.environ.get("MODULES_DIR", "/app/modules"))


class LoadedModule:
    """A module that has been discovered and loaded."""

    def __init__(self, manifest: Manifest, source_path: Path):
        self.manifest = manifest
        self.source_path = source_path
        self.enabled: bool = True
        self._backend_module = None
        self._router = None
        self.error: str | None = None

    @property
    def id(self) -> str:
        return self.manifest.id

    def to_dict(self) -> dict:
        d = self.manifest.to_dict()
        d["enabled"] = self.enabled
        d["has_error"] = self.error is not None
        if self.error:
            d["error"] = self.error
        return d


class ModuleLoader:
    """Discovers, validates, and loads modules."""

    def __init__(self, modules_dir: Path | None = None):
        self.modules_dir = modules_dir or DEFAULT_MODULES_DIR
        self._loaded: dict[str, LoadedModule] = {}

    # ── Discovery ──────────────────────────────────────────────────────

    def discover(self) -> list[Path]:
        """Find all manifest.yaml files under the modules directory."""
        if not self.modules_dir.exists():
            return []
        manifests = sorted(self.modules_dir.glob(f"*/{MANIFEST_FILENAME}"))
        return manifests

    # ── Loading ────────────────────────────────────────────────────────

    def load_all(self) -> list[LoadedModule]:
        """Discover and load all modules. Returns list of loaded modules."""
        manifest_paths = self.discover()
        loaded: list[LoadedModule] = []

        # Parse all manifests first
        parsed: dict[str, tuple[Manifest, Path]] = {}
        for mpath in manifest_paths:
            try:
                manifest = Manifest.from_file(mpath)
                parsed[manifest.id] = (manifest, mpath)
            except (ManifestError, Exception) as exc:
                logger.error("Failed to parse manifest %s: %s", mpath, exc)
                loaded.append(self._make_error(mpath, str(exc)))

        # Validate dependencies / conflicts
        validation_errors = validate_module_set({mid: m for mid, (m, _) in parsed.items()})
        for mid, errors in validation_errors.items():
            manifest, mpath = parsed[mid]
            lm = LoadedModule(manifest, mpath)
            lm.error = "; ".join(errors)
            lm.enabled = False
            self._loaded[mid] = lm
            loaded.append(lm)
            logger.warning("Module '%s' validation failed: %s", mid, lm.error)

        # Load valid modules
        for mid, (manifest, mpath) in parsed.items():
            if mid in validation_errors:
                continue
            lm = self._load_one(manifest, manifest.source_path or mpath.parent)
            self._loaded[mid] = lm
            loaded.append(lm)

        return loaded

    def load_module(self, path: Path) -> LoadedModule:
        """Load a single module from a manifest path."""
        manifest = Manifest.from_file(path)
        lm = self._load_one(manifest, path.parent)
        self._loaded[manifest.id] = lm
        return lm

    def _load_one(self, manifest: Manifest, source_path: Path) -> LoadedModule:
        lm = LoadedModule(manifest, source_path)

        # Import backend entry point
        if manifest.backend_entry:
            try:
                router = self._import_backend(manifest, source_path)
                if router is not None:
                    lm._router = router
            except Exception as exc:
                lm.error = f"Backend import failed: {exc}"
                lm.enabled = False
                logger.error("Module '%s' backend import failed: %s", manifest.id, exc)

        if lm.error is None:
            logger.info("Loaded module '%s' v%s", manifest.id, manifest.version)

        return lm

    def _import_backend(self, manifest: Manifest, source_path: Path):
        """Import the backend entry point module.

        Returns the FastAPI router if the module exports FASTAPI_ROUTER.
        """
        backend_dir = source_path / "backend"
        entry = manifest.backend_entry

        # entry can be "routes" (meaning backend/routes.py) or a dotted path
        parts = entry.replace(".py", "").split(".")
        module_file = backend_dir.joinpath(*parts)
        if module_file.with_suffix(".py").exists():
            module_file = module_file.with_suffix(".py")
        elif (backend_dir / "__init__.py").exists() and (
            backend_dir / f"{'.'.join(parts)}.py"
        ).exists():
            module_file = backend_dir / f"{'.'.join(parts)}.py"
        else:
            # try entry.py directly
            module_file = backend_dir / f"{parts[-1]}.py"

        if not module_file.exists():
            logger.debug(
                "Module '%s': backend entry '%s' not found at %s, skipping",
                manifest.id,
                entry,
                module_file,
            )
            return None

        mod_name = f"_umbryx_ext_{manifest.id}_{parts[-1]}"
        spec = importlib.util.spec_from_file_location(mod_name, module_file)
        if spec is None or spec.loader is None:
            return None

        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)

        # Look for a FASTAPI_ROUTER attribute
        return getattr(mod, "FASTAPI_ROUTER", None)

    def _make_error(self, path: Path, error: str) -> LoadedModule:
        """Create a LoadedModule representing a parse failure."""
        dummy = Manifest.__new__(Manifest)
        dummy.id = path.parent.name
        dummy.name = path.parent.name
        dummy.version = "0.0.0"
        dummy.description = f"Failed to load: {error}"
        lm = LoadedModule.__new__(LoadedModule)
        lm.manifest = dummy
        lm.source_path = path.parent
        lm.enabled = False
        lm.error = error
        lm._backend_module = None
        return lm

    # ── Accessors ──────────────────────────────────────────────────────

    def get(self, module_id: str) -> LoadedModule | None:
        return self._loaded.get(module_id)

    def all(self) -> list[LoadedModule]:
        return list(self._loaded.values())

    def enabled(self) -> list[LoadedModule]:
        return [m for m in self._loaded.values() if m.enabled]


# ── Dependency validation ──────────────────────────────────────────────


def validate_module_set(manifests: dict[str, Manifest]) -> dict[str, list[str]]:
    """Validate dependency and conflict constraints across a set of modules.

    Returns a dict mapping module_id → list of error strings.
    Only modules with errors are included.
    """
    errors: dict[str, list[str]] = {}
    available = set(manifests.keys())

    for mid, manifest in manifests.items():
        errs: list[str] = []

        # Check dependencies
        for dep in manifest.depends_on:
            if dep not in available:
                errs.append(f"Missing dependency: '{dep}'")

        # Check conflicts
        for conflict in manifest.conflicts_with:
            if conflict in available:
                errs.append(f"Conflicts with installed module: '{conflict}'")

        # Self-conflict check
        if mid in manifest.conflicts_with:
            errs.append("Module conflicts with itself")

        # Circular dependency (simple check: direct cycle A→B→A)
        for dep in manifest.depends_on:
            dep_manifest = manifests.get(dep)
            if dep_manifest and mid in dep_manifest.depends_on:
                errs.append(f"Circular dependency: '{mid}' ↔ '{dep}'")

        if errs:
            errors[mid] = errs

    return errors


# ── Global singleton ───────────────────────────────────────────────────

_loader: ModuleLoader | None = None


def get_loader() -> ModuleLoader:
    global _loader
    if _loader is None:
        _loader = ModuleLoader()
    return _loader


def init_loader(modules_dir: Path | None = None) -> ModuleLoader:
    global _loader
    _loader = ModuleLoader(modules_dir)
    return _loader
