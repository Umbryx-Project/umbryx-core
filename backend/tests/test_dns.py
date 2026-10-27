"""
Phase 6 — DNS & External Presence tests.

The legacy /api/dns router (routers/dns.py) was found dead during the
2026-08-14 security audit (F4): it referenced a `models.DNSRecord` class that
no longer exists — the real model, `models.DnsRecord`, has an unrelated
schema (zone_id/provider_id/record_type, no project_id/meta/deleted_at) — so
every request always 500'd, and it had no project-membership check at all.
It has been intentionally unmounted (see routing.py::_register_hosts); DNS
record management now lives at /api/infra-v2/dns/* (routers/dns_api.py).
Only the still-referenced core/dns/manager.py provider unit tests remain.
"""
import asyncio


class TestDNSProviderUnit:
    def test_manual_provider_create(self):
        from app.core.dns.manager import ManualDNSProvider
        p = ManualDNSProvider()
        rid = asyncio.run(
            p.create_record("z1", "test.example.com", "A", "1.2.3.4", 300)
        )
        assert rid.startswith("manual-")

    def test_manual_provider_delete(self):
        from app.core.dns.manager import ManualDNSProvider
        p = ManualDNSProvider()
        ok = asyncio.run(p.delete_record("z1", "r1"))
        assert ok is True

    def test_manual_provider_verify(self):
        from app.core.dns.manager import ManualDNSProvider
        p = ManualDNSProvider()
        ok = asyncio.run(p.verify_record("z1", "r1"))
        assert ok is False

    def test_get_provider(self):
        from app.core.dns.manager import get_provider
        assert get_provider("manual") is not None
        assert get_provider("cloudflare") is None
        assert get_provider("nonexistent") is None
