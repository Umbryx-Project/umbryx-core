"""
Module lifecycle — enable/disable modules at runtime.

Handles:
- Registering/unregistering extensions and object types
- Applying default settings
- Running health checks after enable
- Persisting state to the ``module_states`` table
"""

from __future__ import annotations

from ..logging_setup import get_logger
from .extension_points import ext_registry
from .loader import get_loader
from .object_types import obj_type_registry

logger = get_logger(__name__)


def enable_module(module_id: str) -> tuple[bool, str]:
    """Enable a module at runtime.

    Registers its object types and extension points.
    Returns (success, message).
    """
    loader = get_loader()
    lm = loader.get(module_id)
    if lm is None:
        return False, f"Module '{module_id}' not found"

    if lm.error:
        return False, f"Module '{module_id}' has errors: {lm.error}"

    if lm.enabled:
        return True, f"Module '{module_id}' already enabled"

    # Register object types
    for obj_schema in lm.manifest.objects:
        try:
            obj_type_registry.register(module_id, obj_schema)
        except ValueError as exc:
            return False, str(exc)

    # Register extension points
    ext_registry.register_from_manifest(module_id, lm.manifest.extensions)

    lm.enabled = True
    logger.info("Enabled module '%s'", module_id)
    return True, "OK"


def disable_module(module_id: str) -> tuple[bool, str]:
    """Disable a module at runtime.

    Unregisters its object types and extension points.
    Returns (success, message).
    """
    loader = get_loader()
    lm = loader.get(module_id)
    if lm is None:
        return False, f"Module '{module_id}' not found"

    if not lm.enabled:
        return True, f"Module '{module_id}' already disabled"

    ext_registry.unregister_module(module_id)
    obj_type_registry.unregister_module(module_id)

    lm.enabled = False
    logger.info("Disabled module '%s'", module_id)
    return True, "OK"


def health_check(module_id: str) -> dict:
    """Run a health check for a module.

    Checks:
    - Manifest is valid
    - All dependencies are enabled
    - Object types are registered (if enabled)
    """
    loader = get_loader()
    lm = loader.get(module_id)
    if lm is None:
        return {"module_id": module_id, "status": "not_found"}

    result: dict = {
        "module_id": module_id,
        "status": "healthy" if lm.enabled else "disabled",
        "enabled": lm.enabled,
    }

    if lm.error:
        result["status"] = "error"
        result["error"] = lm.error
        return result

    # Check dependencies
    missing_deps = []
    for dep in lm.manifest.depends_on:
        dep_lm = loader.get(dep)
        if dep_lm is None or not dep_lm.enabled:
            missing_deps.append(dep)

    if missing_deps:
        result["status"] = "degraded"
        result["missing_dependencies"] = missing_deps

    return result


def get_all_states() -> list[dict]:
    """Return state info for all loaded modules."""
    loader = get_loader()
    return [lm.to_dict() for lm in loader.all()]


def activate_loaded_modules(app=None) -> None:
    """Register extensions and object types for all enabled loaded modules.

    Called once during startup after load_all().
    If ``app`` (a FastAPI instance) is provided, also mounts module routers.
    """
    loader = get_loader()
    for lm in loader.enabled():
        if lm.error:
            continue
        for obj_schema in lm.manifest.objects:
            try:
                obj_type_registry.register(lm.id, obj_schema)
            except ValueError as exc:
                logger.warning("Object type registration failed: %s", exc)

        ext_registry.register_from_manifest(lm.id, lm.manifest.extensions)

        if app is not None and getattr(lm, "_router", None) is not None:
            try:
                app.include_router(lm._router)
                logger.info("Mounted router for module '%s'", lm.id)
            except Exception as exc:
                logger.error("Failed to mount router for '%s': %s", lm.id, exc)
