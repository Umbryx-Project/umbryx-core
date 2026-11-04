"""
Regression tests for the 2026-08-30 audit fix: core/infra/dns/acme.py and
core/dns/manager.py made outbound requests without going through
core.ssrf_guard.validate_outbound_url. The ACME client's URLs come from
prior server responses (Location headers / JSON body fields per RFC 8555)
rather than fixed constants, which is the real vector — a compromised or
malicious ACME server could redirect subsequent requests to an internal
address.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException


@pytest.mark.ee
class TestAcmeClientSsrfGuard:
    def _client(self):
        from app.ee.infra.dns.acme import AcmeClient

        with patch.object(AcmeClient, "_fetch_directory", lambda self: None):
            client = AcmeClient(
                directory_url="https://acme-staging-v02.api.letsencrypt.org/directory"
            )
        client._directory = {"newNonce": "https://acme-staging-v02.api.letsencrypt.org/new-nonce"}
        return client

    def test_post_rejects_private_url(self):
        client = self._client()
        with pytest.raises(HTTPException):
            client._post("http://127.0.0.1/finalize", {})

    def test_post_rejects_internal_hostname(self):
        client = self._client()
        with pytest.raises(HTTPException):
            client._post("http://169.254.169.254/latest/meta-data/", {})

    def test_get_nonce_rejects_private_new_nonce_url(self):
        client = self._client()
        client._directory = {"newNonce": "http://10.0.0.5/new-nonce"}
        with pytest.raises(HTTPException):
            client._get_nonce()

    def test_fetch_directory_rejects_private_directory_url(self):
        from app.ee.infra.dns.acme import AcmeClient

        client = AcmeClient.__new__(AcmeClient)
        client._http = MagicMock()
        client.directory_url = "http://192.168.1.1/directory"
        with pytest.raises(HTTPException):
            client._fetch_directory()
        client._http.get.assert_not_called()


class TestCloudflareDnsProviderSsrfGuard:
    @pytest.mark.asyncio
    async def test_create_record_rejects_private_base_url(self):
        from app.core.dns.manager import CloudflareDNSProvider

        provider = CloudflareDNSProvider(api_token="tok")
        provider._base_url = "http://127.0.0.1"
        with pytest.raises(HTTPException):
            await provider.create_record("zone1", "test.example.com", "A", "1.2.3.4", 300)

    @pytest.mark.asyncio
    async def test_delete_record_rejects_private_base_url(self):
        from app.core.dns.manager import CloudflareDNSProvider

        provider = CloudflareDNSProvider(api_token="tok")
        provider._base_url = "http://169.254.169.254"
        with pytest.raises(HTTPException):
            await provider.delete_record("zone1", "rec1")

    @pytest.mark.asyncio
    async def test_verify_record_rejects_private_base_url(self):
        from app.core.dns.manager import CloudflareDNSProvider

        provider = CloudflareDNSProvider(api_token="tok")
        provider._base_url = "http://10.0.0.1"
        with pytest.raises(HTTPException):
            await provider.verify_record("zone1", "rec1")

    def test_default_base_url_is_the_real_cloudflare_host(self):
        # The default _base_url must stay the fixed, well-known Cloudflare
        # API host — the guard added here relies on this never becoming
        # admin/attacker-configurable without deliberately revisiting this
        # test.
        from app.core.dns.manager import CloudflareDNSProvider

        provider = CloudflareDNSProvider(api_token="tok")
        assert provider._base_url == "https://api.cloudflare.com/client/v4"
