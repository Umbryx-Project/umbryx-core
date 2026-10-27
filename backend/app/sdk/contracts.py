from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class HostDTO:
    id: str
    ip: str
    hostname: str = ""
    tags: list[str] = field(default_factory=list)
    status: str = ""


@dataclass
class FindingDTO:
    title: str
    severity: str
    description: str = ""
    host_id: str | None = None
    cred_id: str | None = None


@dataclass
class ConnectorResult:
    ok: bool
    output: str = ""
    structured: dict = field(default_factory=dict)
    entities_created: dict = field(default_factory=dict)
    error: str | None = None


class PluginContext(Protocol):
    project_id: str
    user_id: str
    plugin_id: str

    async def get_hosts(self, tags: list[str] | None = None) -> list[HostDTO]: ...
    async def create_finding(self, f: FindingDTO) -> str: ...
    async def log_job_output(self, job_id: str, line: str) -> None: ...
    async def emit_event(self, event: str, data: dict) -> None: ...


@runtime_checkable
class ConnectorV1(Protocol):
    key: str
    title: str
    category: str
    api_version: int = 1

    async def execute(
        self, operation: str, params: dict, ctx: PluginContext
    ) -> ConnectorResult: ...
    async def health_check(self, config: dict) -> bool: ...


@runtime_checkable
class InfraProviderV1(Protocol):
    key: str
    title: str
    api_version: int = 1

    async def provision(self, spec: dict, params: dict, ctx: PluginContext) -> dict: ...
    async def status(self, resource_ids: dict) -> dict: ...
    async def destroy(self, resource_ids: dict, ctx: PluginContext) -> dict: ...
    async def health_check(self, resource_ids: dict) -> bool: ...


@runtime_checkable
class DNSProviderV1(Protocol):
    key: str
    title: str
    api_version: int = 1

    async def create_record(
        self, zone_id: str, name: str, type: str, value: str, ttl: int
    ) -> str: ...
    async def delete_record(self, zone_id: str, record_id: str) -> bool: ...
    async def verify_record(self, zone_id: str, record_id: str) -> bool: ...


@runtime_checkable
class ScanParserV1(Protocol):
    format_key: str
    api_version: int = 1

    def parse(self, content: bytes | str) -> list[dict]: ...
    def can_parse(self, content: bytes | str) -> bool: ...


@runtime_checkable
class PlaybookStepV1(Protocol):
    step_type: str
    api_version: int = 1

    async def execute(self, step_params: dict, ctx: PluginContext) -> ConnectorResult: ...
    def validate_params(self, step_params: dict) -> list[str]: ...


@runtime_checkable
class NotificationChannelV1(Protocol):
    key: str
    api_version: int = 1

    async def send(self, event: str, payload: dict, config: dict) -> bool: ...
