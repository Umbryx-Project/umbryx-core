"""Unified DNS path — ServiceLink a_record config goes through DnsManager
(known gap #4, ARCHITECTURE.md §3).

links._configure_dns used to be an inline cloudflare-only httpx call that
matched provider type 'cloudflare' and left no DnsRecord row. It now goes
through DnsManager.upsert_domain_record: any registered DNS adapter
(cloudflare_dns, route53_dns, ...), a tracked DnsRecord linked to the
redirector service, and teardown cleanup via delete_records_for_object.
"""

import pytest

# Enterprise-only: this module imports app.ee at import time, so in a
# Community tree (where the package is removed by scripts/build-ce.sh)
# there is nothing to test rather than something failing. Declared here
# instead of in a list in conftest, so a module that stops depending on
# the Enterprise package can drop the line with it.
pytest.importorskip("app.ee", reason="Enterprise Edition package not in this build")

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.ee.infra.dns.manager import DnsManager
from app.models.dns import DnsZone
from app.models.infra_v2 import InfraProvider, InfraStack, ServiceLink, StackService

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _make_env(db, domain="cdn.example.com"):
    dns_provider = InfraProvider(
        id=new_id("prv"),
        name="dns",
        type="cloudflare_dns",
        category="dns",
        host="",
        connection={"api_token": "tok"},
        created_at=ts_now(),
    )
    web_provider = InfraProvider(
        id=new_id("prv"),
        name="edge",
        type="manual",
        category="cloud",
        host="203.0.113.50",
        created_at=ts_now(),
    )
    db.add_all([dns_provider, web_provider])
    db.flush()
    zone = DnsZone(
        id=new_id("zn"),
        provider_id=dns_provider.id,
        zone_name="example.com",
        authorized=True,
    )
    db.add(zone)
    stack = InfraStack(
        id=new_id("stk"), name=f"dns-{new_id('s')[:6]}", status="ready", mode="standalone",
        created_at=ts_now(),
    )
    db.add(stack)
    db.flush()
    redir = StackService(
        id=new_id("svc"), stack_id=stack.id, provider_id=dns_provider.id,
        role="redirector", name="cdn", status="running",
    )
    web = StackService(
        id=new_id("svc"), stack_id=stack.id, provider_id=web_provider.id,
        role="c2", name="c2", status="running",
    )
    db.add_all([redir, web])
    db.flush()
    lnk = ServiceLink(
        id=new_id("lnk"), stack_id=stack.id,
        from_service_id=redir.id, to_service_id=web.id,
        link_type="a_record", config={"domain": domain},
        status="pending",
    )
    db.add(lnk)
    db.commit()
    return stack, lnk, redir, web, dns_provider, zone


class TestUpsertDomainRecord:
    def test_creates_tracked_record(self, module_client, module_db):
        stack, lnk, redir, web, prv, zone = _make_env(module_db)

        fake = MagicMock()
        ret = MagicMock(success=True, record_id="cf-rec-1", value="203.0.113.50", ttl=120)
        ret.name = "cdn"
        fake.create_record.return_value = ret
        with patch.object(DnsManager, "_get_adapter", return_value=(fake, {"api_token": "tok"})):
            rec = DnsManager(module_db).upsert_domain_record(
                prv, "cdn.example.com", "203.0.113.50",
                linked_object_type="service", linked_object_id=redir.id, ttl=120,
            )
        assert rec is not None
        assert rec.zone_id == zone.id
        assert rec.name == "cdn", "record name is the domain minus the zone suffix"
        assert rec.value == "203.0.113.50"
        assert rec.remote_record_id == "cf-rec-1"
        assert rec.linked_object_id == redir.id
        spec = fake.create_record.call_args.args[0]
        assert spec.zone == "example.com" and spec.name == "cdn"

    def test_updates_existing(self, module_client, module_db):
        stack, lnk, redir, web, prv, zone = _make_env(module_db, domain="old.example.com")
        from app.models.dns import DnsRecord

        db = module_db
        db.add(
            DnsRecord(
                id=new_id("dnsr"), zone_id=zone.id, provider_id=prv.id,
                name="old", record_type="A", value="198.51.100.1", ttl=120,
                remote_record_id="cf-old", status="active",
                linked_object_type="service", linked_object_id=redir.id,
            )
        )
        db.commit()

        fake = MagicMock()
        fake.update_record.return_value = MagicMock(success=True)
        with patch.object(DnsManager, "_get_adapter", return_value=(fake, {})):
            rec = DnsManager(db).upsert_domain_record(
                prv, "old.example.com", "203.0.113.51",
                linked_object_type="service", linked_object_id=redir.id,
            )
        assert rec is not None and rec.value == "203.0.113.51"
        fake.update_record.assert_called_once()
        fake.create_record.assert_not_called()

    def test_no_zone_returns_none(self, module_client, module_db):
        stack, lnk, redir, web, prv, zone = _make_env(module_db, domain="cdn.unregistered.io")
        with patch.object(
            DnsManager, "_get_adapter", return_value=(MagicMock(), {})
        ):
            assert (
                DnsManager(module_db).upsert_domain_record(
                    prv, "cdn.unregistered.io", "203.0.113.50",
                    linked_object_type="service", linked_object_id=redir.id,
                )
                is None
            )


class TestLinkConfiguresDns:
    def test_a_record_link_via_dns_manager(self, module_client, module_db):
        from app.ee.infra.links import LinkManager

        stack, lnk, redir, web, prv, zone = _make_env(module_db)
        fake = MagicMock()
        ret = MagicMock(success=True, record_id="cf-rec-2", value="203.0.113.50", ttl=120)
        ret.name = "cdn"
        fake.create_record.return_value = ret
        with patch.object(DnsManager, "_get_adapter", return_value=(fake, {})):
            LinkManager(module_db)._configure_dns(stack, lnk, redir, web)
        module_db.commit()  # pipeline caller commits link status

        module_db.expire_all()
        assert lnk.status == "configured"
        from app.models.dns import DnsRecord

        rows = module_db.query(DnsRecord).filter(DnsRecord.linked_object_id == redir.id).all()
        assert rows, "link-created record must be tracked as DnsRecord"

    def test_zone_missing_link_skips_not_errors(self, module_client, module_db):
        from app.ee.infra.links import LinkManager

        stack, lnk, redir, web, prv, zone = _make_env(module_db, domain="x.unregistered.io")
        with patch.object(DnsManager, "_get_adapter", return_value=(MagicMock(), {})):
            LinkManager(module_db)._configure_dns(stack, lnk, redir, web)
        module_db.commit()
        module_db.expire_all()
        assert lnk.status == "skipped"

    def test_dns_provider_type_not_cloudflare_literal(self, module_client, module_db):
        """The old code required type == 'cloudflare' and skipped the real
        'cloudflare_dns' adapter type — the unified path accepts it."""
        from app.ee.infra.links import LinkManager

        stack, lnk, redir, web, prv, zone = _make_env(module_db)
        fake = MagicMock()
        ret = MagicMock(success=True, record_id="cf-3", value="203.0.113.50", ttl=120)
        ret.name = "cdn"
        fake.create_record.return_value = ret
        with patch.object(DnsManager, "_get_adapter", return_value=(fake, {})):
            LinkManager(module_db)._configure_dns(stack, lnk, redir, web)
        assert lnk.status == "configured"
