"""
Object type registry — central catalog of all object types defined by manifests.

When a module declares an ``objects:`` section in its manifest, those types
are registered here so the universal object model API can validate and
schema-drive CRUD operations.
"""

from __future__ import annotations

import threading
from typing import Any

from .manifest import ObjectTypeSchema


class ObjectTypeRegistry:
    """Thread-safe registry mapping ``type`` → ``ObjectTypeSchema``."""

    def __init__(self):
        self._lock = threading.RLock()
        self._types: dict[str, tuple[str, ObjectTypeSchema]] = {}

    def register(self, module_id: str, schema: ObjectTypeSchema) -> None:
        with self._lock:
            if schema.type in self._types:
                existing_module = self._types[schema.type][0]
                if existing_module != module_id:
                    raise ValueError(
                        f"Object type '{schema.type}' already registered by "
                        f"module '{existing_module}'"
                    )
            self._types[schema.type] = (module_id, schema)

    def unregister_module(self, module_id: str) -> None:
        with self._lock:
            for key in list(self._types.keys()):
                if self._types[key][0] == module_id:
                    del self._types[key]

    def get(self, type_name: str) -> ObjectTypeSchema | None:
        with self._lock:
            pair = self._types.get(type_name)
            return pair[1] if pair else None

    def get_module(self, type_name: str) -> str | None:
        with self._lock:
            pair = self._types.get(type_name)
            return pair[0] if pair else None

    def all_types(self) -> dict[str, dict]:
        with self._lock:
            return {
                name: {**schema.to_dict(), "module_id": mod}
                for name, (mod, schema) in self._types.items()
            }

    def validate_data(self, type_name: str, data: dict) -> list[str]:
        """Validate a data dict against the object type schema.

        Returns a list of error messages (empty = valid).
        """
        schema = self.get(type_name)
        if schema is None:
            return [f"Unknown object type '{type_name}'"]

        errors: list[str] = []

        for field_def in schema.fields:
            val = data.get(field_def.name, field_def.default)

            if field_def.required and (val is None or val == ""):
                errors.append(f"Field '{field_def.name}' is required")
                continue

            if val is None:
                continue

            type_err = self._check_type(field_def, val)
            if type_err:
                errors.append(type_err)

        return errors

    @staticmethod
    def _check_type(field_def, val: Any) -> str | None:
        ftype = field_def.type
        if ftype == "string" and not isinstance(val, str):
            return f"Field '{field_def.name}' must be a string"
        if ftype == "text" and not isinstance(val, str):
            return f"Field '{field_def.name}' must be text (string)"
        if ftype == "integer" and (isinstance(val, bool) or not isinstance(val, int)):
            return f"Field '{field_def.name}' must be an integer"
        if ftype == "float" and not isinstance(val, int | float):
            return f"Field '{field_def.name}' must be a number"
        if ftype == "boolean" and not isinstance(val, bool):
            return f"Field '{field_def.name}' must be a boolean"
        if ftype == "enum":
            if not isinstance(val, str) or (field_def.options and val not in field_def.options):
                return f"Field '{field_def.name}' must be one of {field_def.options}"
        if ftype == "json" and not isinstance(val, dict | list):
            return f"Field '{field_def.name}' must be a JSON object or array"
        return None

    def clear(self) -> None:
        with self._lock:
            self._types.clear()


# Global singleton
obj_type_registry = ObjectTypeRegistry()
