from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from enum import StrEnum

logger = logging.getLogger(__name__)


class PlatformEvent(StrEnum):
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    HOST_CREATED = "host.created"
    HOST_STATUS_CHANGED = "host.status_changed"
    FINDING_CREATED = "finding.created"
    PROJECT_CLOSED = "project.closed"
    INFRA_READY = "infra.ready"
    INFRA_DESTROYED = "infra.destroyed"
    INFRA_INTEGRATED = "infra.integrated"
    PLUGIN_INSTALLED = "plugin.installed"
    PLUGIN_UNINSTALLED = "plugin.uninstalled"


class PluginEventBus:
    def __init__(self):
        self._handlers: dict[str, list[Callable]] = defaultdict(list)

    def subscribe(self, event: PlatformEvent | str, handler: Callable) -> None:
        self._handlers[str(event)].append(handler)

    def on(self, event: PlatformEvent | str):
        def decorator(func: Callable):
            self.subscribe(event, func)
            return func

        return decorator

    async def emit(self, event: PlatformEvent | str, payload: dict | None = None) -> None:
        event_key = str(event)
        handlers = self._handlers.get(event_key, [])
        for handler in handlers:
            try:
                result = handler(payload or {})
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.warning(
                    "Event handler %s failed for %s",
                    getattr(handler, "__name__", "?"),
                    event_key,
                    exc_info=True,
                )

    def clear(self) -> None:
        self._handlers.clear()

    def listeners(self, event: PlatformEvent | str | None = None) -> list[Callable]:
        if event is not None:
            return list(self._handlers.get(str(event), []))
        return [h for hs in self._handlers.values() for h in hs]


event_bus = PluginEventBus()
