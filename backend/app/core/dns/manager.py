from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from ..ssrf_guard import validate_outbound_url

logger = logging.getLogger(__name__)


@runtime_checkable
class DNSProvider(Protocol):
    key: str

    async def create_record(
        self, zone_id: str, name: str, type: str, value: str, ttl: int
    ) -> str: ...
    async def delete_record(self, zone_id: str, record_id: str) -> bool: ...
    async def verify_record(self, zone_id: str, record_id: str) -> bool: ...


class ManualDNSProvider:
    key = "manual"

    async def create_record(self, zone_id: str, name: str, type: str, value: str, ttl: int) -> str:
        logger.info(
            "MANUAL DNS: create %s %s → %s (ttl=%d, zone=%s)", type, name, value, ttl, zone_id
        )
        return f"manual-{name}"

    async def delete_record(self, zone_id: str, record_id: str) -> bool:
        logger.info("MANUAL DNS: delete record %s from zone %s", record_id, zone_id)
        return True

    async def verify_record(self, zone_id: str, record_id: str) -> bool:
        return False


class CloudflareDNSProvider:
    key = "cloudflare"

    def __init__(self, api_token: str):
        self._api_token = api_token
        self._base_url = "https://api.cloudflare.com/client/v4"

    async def create_record(self, zone_id: str, name: str, type: str, value: str, ttl: int) -> str:
        import httpx

        url = f"{self._base_url}/zones/{zone_id}/dns_records"
        validate_outbound_url(url)
        async with httpx.AsyncClient() as client:
            r = await client.post(
                url,
                headers={"Authorization": f"Bearer {self._api_token}"},
                json={"type": type, "name": name, "content": value, "ttl": ttl},
            )
            data = r.json()
            if data.get("success"):
                return data["result"]["id"]
            raise RuntimeError(f"Cloudflare API error: {data.get('errors', [])}")

    async def delete_record(self, zone_id: str, record_id: str) -> bool:
        import httpx

        url = f"{self._base_url}/zones/{zone_id}/dns_records/{record_id}"
        validate_outbound_url(url)
        async with httpx.AsyncClient() as client:
            r = await client.delete(
                url,
                headers={"Authorization": f"Bearer {self._api_token}"},
            )
            return r.json().get("success", False)

    async def verify_record(self, zone_id: str, record_id: str) -> bool:
        import httpx

        url = f"{self._base_url}/zones/{zone_id}/dns_records/{record_id}"
        validate_outbound_url(url)
        async with httpx.AsyncClient() as client:
            r = await client.get(
                url,
                headers={"Authorization": f"Bearer {self._api_token}"},
            )
            return r.json().get("success", False)


_providers: dict[str, DNSProvider] = {
    "manual": ManualDNSProvider(),
}


def register_provider(provider: DNSProvider):
    _providers[provider.key] = provider


def get_provider(key: str) -> DNSProvider | None:
    return _providers.get(key)


async def create_dns_record(
    provider_key: str, zone_id: str, name: str, type: str, value: str, ttl: int = 300
) -> str:
    p = get_provider(provider_key)
    if not p:
        raise ValueError(f"Unknown DNS provider: {provider_key}")
    return await p.create_record(zone_id, name, type, value, ttl)


async def delete_dns_record(provider_key: str, zone_id: str, record_id: str) -> bool:
    p = get_provider(provider_key)
    if not p:
        raise ValueError(f"Unknown DNS provider: {provider_key}")
    return await p.delete_record(zone_id, record_id)


async def verify_dns_record(provider_key: str, zone_id: str, record_id: str) -> bool:
    p = get_provider(provider_key)
    if not p:
        return False
    return await p.verify_record(zone_id, record_id)
