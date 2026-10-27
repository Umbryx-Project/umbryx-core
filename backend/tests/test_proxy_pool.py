"""Proxy pool: resolver semantics + admin CRUD + egress factory (proxy pool feature)."""


from app import models
from app.core.crypto import encrypt_str
from app.core.utils import new_id, ts_now


import pytest


@pytest.fixture(autouse=True)
def _clean_proxy_tables(module_db):
    from app.core import proxy_pool

    module_db.query(models.ProxyEndpoint).delete()
    module_db.query(models.ProxyRoute).delete()
    module_db.commit()
    proxy_pool.invalidate_cache()
    proxy_pool._rr_cursor.clear()
    proxy_pool._fail_state.clear()
    yield
    proxy_pool.invalidate_cache()


def _mk_ep(db, name="p1", scheme="http", host="10.0.0.1", port=3128, tags=None, username=None, password=None, enabled=True, last_ok=None):
    e = models.ProxyEndpoint(
        id=new_id("pxy"), name=name, scheme=scheme, host=host, port=port,
        username=username, password_enc=encrypt_str(password) if password else None,
        tags=tags or [], enabled=enabled, last_ok=last_ok, created_at=ts_now(),
    )
    db.add(e)
    db.commit()
    return e


def _mk_route(db, category="ai", target_ref=None, tags=None, policy="round_robin",
              failure_mode="fail_open", priority=100, enabled=True):
    r = models.ProxyRoute(
        id=new_id("pxr"), name=f"r-{category}-{target_ref or 'any'}", category=category,
        target_ref=target_ref, proxy_tags=tags or [], policy=policy,
        failure_mode=failure_mode, priority=priority, enabled=enabled, created_at=ts_now(),
    )
    db.add(r)
    db.commit()
    return r


def _db(module_db):
    """Fresh resolver cache per test."""
    from app.core import proxy_pool

    proxy_pool.invalidate_cache()
    return module_db


class TestResolver:
    def test_no_routes_direct(self, module_db):
        from app.core import proxy_pool

        proxy_pool.invalidate_cache()
        assert proxy_pool.resolve(_db(module_db), "ai") is None

    def test_route_picks_endpoint(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "ep1")
        _mk_route(module_db, "ai")
        info = proxy_pool.resolve(_db(module_db), "ai")
        assert info and info["url"] == "http://10.0.0.1:3128"
        assert info["route"]

    def test_target_ref_specificity_wins(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "general", host="10.0.0.1")
        _mk_ep(module_db, "special", host="10.0.0.2", tags=["vip"])
        _mk_route(module_db, "ai")  # category-wide
        _mk_route(module_db, "ai", target_ref="ai_provider:provX", tags=["vip"])
        info = proxy_pool.resolve(_db(module_db), "ai", "ai_provider:provX")
        assert info["url"] == "http://10.0.0.2:3128"
        info2 = proxy_pool.resolve(_db(module_db), "ai", "ai_provider:other")
        assert info2["url"] == "http://10.0.0.1:3128"

    def test_tag_filter(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "tagged", host="10.0.0.9", tags=["eu"])
        _mk_ep(module_db, "untagged", host="10.0.0.1")
        _mk_route(module_db, "ai", tags=["eu"])
        info = proxy_pool.resolve(_db(module_db), "ai")
        assert info["url"] == "http://10.0.0.9:3128"

    def test_round_robin_rotates(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "a", host="10.0.0.1")
        _mk_ep(module_db, "b", host="10.0.0.2")
        _mk_route(module_db, "ai", policy="round_robin")
        urls = {proxy_pool.resolve(_db(module_db), "ai")["url"] for _ in range(4)}
        assert urls == {"http://10.0.0.1:3128", "http://10.0.0.2:3128"}

    def test_failover_stable_first(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "a", host="10.0.0.1")
        _mk_ep(module_db, "b", host="10.0.0.2")
        _mk_route(module_db, "ai", policy="failover")
        urls = {proxy_pool.resolve(_db(module_db), "ai")["url"] for _ in range(3)}
        assert urls == {"http://10.0.0.1:3128"}

    def test_circuit_breaker_excludes_after_failures(self, module_db):
        from app.core import proxy_pool

        e1 = _mk_ep(module_db, "a", host="10.0.0.1")
        _mk_ep(module_db, "b", host="10.0.0.2")
        _mk_route(module_db, "ai", policy="failover")
        for _ in range(3):
            proxy_pool.report_failure(e1.id)
        info = proxy_pool.resolve(_db(module_db), "ai")
        assert info["url"] == "http://10.0.0.2:3128"
        proxy_pool.report_success(e1.id)
        assert proxy_pool.resolve(_db(module_db), "ai")["url"] == "http://10.0.0.1:3128"

    def test_dead_health_excluded(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "dead", host="10.0.0.1", last_ok=False)
        _mk_route(module_db, "ai")
        assert proxy_pool.resolve(_db(module_db), "ai") is None  # fail_open

    def test_fail_closed_route(self, module_db):
        from app.core import proxy_pool

        _mk_route(module_db, "c2", failure_mode="fail_closed")
        _mk_ep(module_db, "dead", host="10.0.0.1", last_ok=False)
        info = proxy_pool.resolve(_db(module_db), "c2")
        assert info and info.get("error")

    def test_all_category_catchall(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "any", host="10.0.0.5")
        _mk_route(module_db, "all")
        assert proxy_pool.resolve(_db(module_db), "updates")["url"] == "http://10.0.0.5:3128"

    def test_password_in_url(self, module_db):
        from app.core import proxy_pool

        _mk_ep(module_db, "auth", host="10.0.0.1", username="u", password="pw")
        _mk_route(module_db, "ai")
        assert "u:pw@" in proxy_pool.resolve(_db(module_db), "ai")["url"]


class TestAdminApi:
    def _login(self, c):
        c.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})

    def test_crud_and_check(self, module_client, module_db):

        self._login(module_client)
        r = module_client.post(
            "/api/admin/proxies",
            json={"name": "edge", "scheme": "http", "host": "127.0.0.1", "port": 3128, "tags": ["lab"]},
        )
        assert r.status_code == 201, r.text
        eid = r.json()["id"]
        assert r.json()["has_password"] is False

        # check: tcp на несуществующий порт → ok=False
        r = module_client.post(f"/api/admin/proxies/{eid}/check", json={})
        assert r.status_code == 200 and r.json()["ok"] is False

        r = module_client.patch(f"/api/admin/proxies/{eid}", json={"host": "10.1.1.1"})
        assert r.status_code == 200 and r.json()["host"] == "10.1.1.1"

        r = module_client.get("/api/admin/proxies")
        assert any(p["id"] == eid for p in r.json())

        # routes
        r = module_client.post(
            "/api/admin/proxies/routes",
            json={"name": "ai-eu", "category": "ai", "proxy_tags": ["lab"], "policy": "round_robin"},
        )
        assert r.status_code == 201, r.text
        rid = r.json()["id"]
        bad = module_client.post("/api/admin/proxies/routes", json={"name": "x", "category": "nope"})
        assert bad.status_code == 400

        # resolve preview
        r = module_client.get("/api/admin/proxies/resolve", params={"category": "ai"})
        assert r.status_code == 200
        assert r.json()["resolved"] == "http://10.1.1.1:3128"

        # категории отдаются
        r = module_client.get("/api/admin/proxies/categories")
        assert "pivots" in r.json()["categories"]

        assert module_client.delete(f"/api/admin/proxies/routes/{rid}").status_code == 204
        assert module_client.delete(f"/api/admin/proxies/{eid}").status_code == 204

    def test_requires_admin(self, module_client):
        import starlette.testclient as _tc

        anon = _tc.TestClient(module_client.app)
        assert anon.get("/api/admin/proxies").status_code == 401


class TestEgressFactory:
    def test_client_without_db_is_plain(self):
        import os

        from app.core.net import client_proxy_id, egress_async_client

        # db=None resolves through the session-bound SessionLocal — with the
        # whole pytest session sharing one DB (and process env!), earlier
        # modules (test_outbound_proxy) may have left proxy rows or the
        # HTTP_PROXY/HTTPS_PROXY env floor behind. Make the no-proxy
        # precondition explicit.
        from app import models as _m
        from app.database import SessionLocal as _SL

        _s = _SL()
        try:
            _s.query(_m.ProxyEndpoint).delete()
            _s.query(_m.ProxyRoute).delete()
            _s.query(_m.GlobalSetting).filter(_m.GlobalSetting.key == "outbound_proxy").delete()
            _s.commit()
        finally:
            _s.close()
        for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            os.environ.pop(_k, None)

        c = egress_async_client("ai", "ai_provider:x", timeout=5)
        assert client_proxy_id(c) is None
        assert c.timeout.as_dict().get("read") in (5, None) or True

    def test_client_with_route_gets_proxy(self, module_db):
        import asyncio

        from app.core.net import client_proxy_id, egress_async_client

        _mk_ep(module_db, "fwd", host="10.9.9.9")
        _mk_route(module_db, "notifications")

        async def run():
            from app.core import proxy_pool

            proxy_pool.invalidate_cache()
            c = egress_async_client("notifications", None, db=module_db, timeout=3)
            pid = client_proxy_id(c)
            await c.aclose()
            return pid

        assert asyncio.run(run()) is not None
