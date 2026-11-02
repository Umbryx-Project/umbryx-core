"""
Extension point registry — formalized hooks that modules register into.

Each extension point is a named slot (e.g. ``sidebar.nav``, ``dashboard.widget``)
that modules populate via their manifest's ``extensions:`` section.

The registry aggregates entries from all enabled manifests and provides
typed accessors for the UI layer.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .manifest import ExtensionPointEntry


@dataclass
class ExtensionEntry:
    """A concrete registration in an extension point."""

    module_id: str
    point: str
    data: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "module_id": self.module_id,
            "point": self.point,
            **self.data,
        }


class ExtensionPointRegistry:
    """Thread-safe registry for extension point entries."""

    def __init__(self):
        self._lock = threading.RLock()
        self._entries: dict[str, list[ExtensionEntry]] = defaultdict(list)

    def register(self, module_id: str, point: str, data: dict) -> None:
        with self._lock:
            self._entries[point].append(ExtensionEntry(module_id=module_id, point=point, data=data))

    def register_from_manifest(self, module_id: str, extensions: list[ExtensionPointEntry]) -> None:
        for ext in extensions:
            self.register(module_id, ext.point, ext.data)

    def unregister_module(self, module_id: str) -> None:
        with self._lock:
            for point in list(self._entries.keys()):
                self._entries[point] = [e for e in self._entries[point] if e.module_id != module_id]
                if not self._entries[point]:
                    del self._entries[point]

    def get(self, point: str) -> list[ExtensionEntry]:
        with self._lock:
            return list(self._entries.get(point, []))

    def get_dicts(self, point: str) -> list[dict]:
        return [e.to_dict() for e in self.get(point)]

    def get_for_module(self, module_id: str, point: str | None = None) -> list[ExtensionEntry]:
        with self._lock:
            result = []
            for p, entries in self._entries.items():
                if point and p != point:
                    continue
                result.extend(e for e in entries if e.module_id == module_id)
            return result

    def all_points(self) -> dict[str, list[dict]]:
        with self._lock:
            return {
                point: [e.to_dict() for e in entries] for point, entries in self._entries.items()
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# Global singleton
ext_registry = ExtensionPointRegistry()
