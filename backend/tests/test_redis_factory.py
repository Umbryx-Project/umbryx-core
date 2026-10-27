"""Tests for app.core.redis_factory — Sentinel HA support."""

import pytest
from unittest.mock import MagicMock, patch

from app.core.redis_factory import (
    _parse_sentinel_hosts,
    create_redis_connection,
    create_redis_sync,
)


class TestParseSentinelHosts:
    def test_parse_sentinel_hosts_basic(self):
        result = _parse_sentinel_hosts("host1:26379,host2:26379,host3:26379")
        assert result == [("host1", 26379), ("host2", 26379), ("host3", 26379)]

    def test_parse_sentinel_hosts_default_port(self):
        result = _parse_sentinel_hosts("host1,host2")
        assert result == [("host1", 26379), ("host2", 26379)]

    def test_parse_sentinel_hosts_mixed(self):
        result = _parse_sentinel_hosts("host1:26379,host2")
        assert result == [("host1", 26379), ("host2", 26379)]

    def test_parse_sentinel_hosts_empty(self):
        result = _parse_sentinel_hosts("")
        assert result == []

    def test_parse_sentinel_hosts_whitespace(self):
        result = _parse_sentinel_hosts("  host1:26379 , host2:26380  ")
        assert result == [("host1", 26379), ("host2", 26380)]

    def test_parse_sentinel_hosts_single(self):
        result = _parse_sentinel_hosts("sentinel.example.com:26379")
        assert result == [("sentinel.example.com", 26379)]


class TestCreateRedisConnection:
    def test_create_redis_without_sentinel(self):
        with patch.dict("os.environ", {"REDIS_SENTINEL_HOSTS": "", "REDIS_URL": "redis://localhost:6379/0", "REDIS_PASSWORD": ""}):
            conn = create_redis_connection()
            assert conn is not None

    def test_create_redis_sentinel_fallback(self):
        with patch.dict("os.environ", {"REDIS_SENTINEL_HOSTS": "badhost:99999", "REDIS_URL": "redis://localhost:6379/0", "REDIS_SENTINEL_MASTER": "mymaster", "REDIS_PASSWORD": ""}):
            with patch("app.core.redis_factory._parse_sentinel_hosts", return_value=[("badhost", 99999)]):
                conn = create_redis_connection()
                assert conn is not None


class TestCreateRedisSync:
    def test_create_redis_sync_without_sentinel(self):
        with patch.dict("os.environ", {"REDIS_SENTINEL_HOSTS": "", "REDIS_URL": "redis://localhost:6379/0", "REDIS_PASSWORD": ""}):
            conn = create_redis_sync()
            assert conn is not None
