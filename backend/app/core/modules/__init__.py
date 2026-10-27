"""
Umbryx module framework.

Provides a declarative manifest system for building extensible modules:

- ``manifest.py`` — YAML manifest parsing and validation
- ``extension_points.py`` — Registry for UI extension slots
- ``object_types.py`` — Registry for universal object model schemas
- ``loader.py`` — Discovers and loads modules from ``/modules/``
- ``validator.py`` — Manifest structural validation
- ``lifecycle.py`` — Runtime enable/disable/health
"""

from .extension_points import ExtensionPointRegistry, ext_registry
from .lifecycle import (
    activate_loaded_modules,
    disable_module,
    enable_module,
    get_all_states,
    health_check,
)
from .loader import LoadedModule, ModuleLoader, get_loader, init_loader
from .manifest import Manifest, ManifestError, ObjectFieldSchema, ObjectTypeSchema
from .object_types import ObjectTypeRegistry, obj_type_registry
from .validator import validate_module

__all__ = [
    "Manifest",
    "ManifestError",
    "ObjectFieldSchema",
    "ObjectTypeSchema",
    "LoadedModule",
    "ModuleLoader",
    "get_loader",
    "init_loader",
    "validate_module",
    "enable_module",
    "disable_module",
    "health_check",
    "get_all_states",
    "activate_loaded_modules",
    "ExtensionPointRegistry",
    "ext_registry",
    "ObjectTypeRegistry",
    "obj_type_registry",
]
