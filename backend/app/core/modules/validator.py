"""
Module validator — standalone validation utilities.

These functions can be used both during loading (by the loader) and
on-demand (e.g. before installing a new module) to check that a manifest
conforms to all structural and semantic rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manifest import Manifest


def validate_module(manifest: Manifest) -> list[str]:
    """Validate a single manifest.

    Returns a list of error messages. Empty list = valid.
    """
    errors: list[str] = []

    # Check object type field uniqueness
    for obj in manifest.objects:
        seen = set()
        for field_def in obj.fields:
            if field_def.name in seen:
                errors.append(f"Object '{obj.type}': duplicate field '{field_def.name}'")
            seen.add(field_def.name)

        # Check list_columns reference valid fields
        field_names = {f.name for f in obj.fields}
        for col in obj.list_columns:
            if col not in field_names:
                errors.append(
                    f"Object '{obj.type}': list_column '{col}' " f"is not a defined field"
                )

        # Check enum fields have options
        for field_def in obj.fields:
            if field_def.type == "enum" and not field_def.options:
                errors.append(
                    f"Object '{obj.type}': field '{field_def.name}' " f"is enum but has no options"
                )
            if field_def.type == "reference" and not field_def.reference_type:
                errors.append(
                    f"Object '{obj.type}': field '{field_def.name}' "
                    f"is reference but has no reference_type"
                )

    # Check setting key uniqueness
    seen_keys = set()
    for setting in manifest.settings:
        if setting.key in seen_keys:
            errors.append(f"Duplicate setting key: '{setting.key}'")
        seen_keys.add(setting.key)

    # Check extension entry has 'id'
    for ext in manifest.extensions:
        if "id" not in ext.data:
            errors.append(f"Extension in '{ext.point}' missing required 'id' field")

    return errors
