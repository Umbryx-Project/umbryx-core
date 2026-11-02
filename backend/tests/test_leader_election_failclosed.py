"""Leader election semantics (review 2026-10-30, E-7).

The None-vs-broken distinction matters: None (Redis genuinely not
configured, single instance) means "no contention — leader"; a BROKEN
client (bad URL, TLS failure) must fail CLOSED, or a misconfigured node
self-appoints alongside a healthy leader and offensive schedules fire
twice — the exact incident the F8 audit note describes.
"""

import pytest

from app.core.leader_election import (
    _RENEW_SCRIPT,
    acquire_lease,
    broken_redis_sentinel,
    get_redis_client,
)


class _FakeRedis:
    def __init__(self, initial_owner=None, fail=False):
        self.store = {} if initial_owner is None else {"umbryx:leader:x": initial_owner}
        self.fail = fail

    async def set(self, key, value, nx=False, ex=None):
        if self.fail:
            raise ConnectionError("down")
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def eval(self, script, numkeys, key, instance, ttl):
        if self.fail:
            raise ConnectionError("down")
        if script == _RENEW_SCRIPT and self.store.get(key) == instance:
            return 1
        return 0


class TestAcquireLease:
    async def test_unconfigured_means_leader(self):
        assert await acquire_lease("x", None) is True

    async def test_fresh_acquire_wins(self):
        r = _FakeRedis()
        assert await acquire_lease("x", r) is True
        assert r.store["umbryx:leader:x"]

    async def test_renew_only_when_owner(self):
        r = _FakeRedis(initial_owner="someone-else")
        assert await acquire_lease("x", r) is False  # lease held elsewhere

    async def test_redis_error_fails_closed(self):
        r = _FakeRedis(fail=True)
        assert await acquire_lease("x", r) is False


class TestBrokenSentinel:
    async def test_broken_construction_takes_no_leader_role(self):
        assert await acquire_lease("x", broken_redis_sentinel()) is False

    async def test_broken_renewal_also_fails_closed(self):
        # renewal_loop uses the same acquire path — the sentinel must
        # never let a broken node renew its way back into leadership
        assert await acquire_lease("x", broken_redis_sentinel()) is False


class TestGetRedisClient:
    def test_no_redis_url_means_none(self, monkeypatch):
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_SENTINEL_HOSTS", raising=False)
        # REDIS_URL unset → factory returns None (unconfigured)
        assert get_redis_client() is None

    def test_bad_url_raises_not_none(self, monkeypatch):
        # a malformed URL must RAISE (distinguishable from unconfigured),
        # never silently return None — that would fail OPEN
        monkeypatch.setenv("REDIS_URL", "not-a-valid-redis-url://")
        with pytest.raises(Exception):  # noqa: B017 — fail-closed contract: ANY error beats silence
            get_redis_client()
