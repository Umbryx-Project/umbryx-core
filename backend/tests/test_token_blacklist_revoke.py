"""token_blacklist: sync revocation flavours + session-wide revoke.

The Shannon 2026-10-29 additions shipped without tests:
blacklist_token_sync / is_blacklisted_sync (AUTH-04 single-use MFA
tokens outside the async request flow) and revoke_all_user_sessions /
user_sessions_revoked (AUTH-05: password change kills every session
issued before it)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.core.token_blacklist as mod
from app.core.token_blacklist import (
    _KEY_PREFIX,
    blacklist_token_sync,
    is_blacklisted_sync,
    revoke_all_user_sessions,
    user_sessions_revoked,
)


@pytest.fixture(autouse=True)
def _reset_client():
    yield
    mod._client = None


def _sync_client(get_value=None, exc=None):
    c = MagicMock()
    if exc is not None:
        c.get.side_effect = exc
        c.setex.side_effect = exc
    else:
        c.get.return_value = get_value
    return c


class TestBlacklistTokenSync:
    def test_empty_jti_is_a_noop(self):
        with patch.object(mod, "_get_sync_client") as g:
            blacklist_token_sync("", 9999999999)
            g.assert_not_called()

    def test_no_client_is_a_noop(self):
        with patch.object(mod, "_get_sync_client", return_value=None):
            assert blacklist_token_sync("jti-sync-1", 9999999999) is None

    def test_sets_key_with_ttl(self):
        c = _sync_client()
        with (
            patch.object(mod, "_get_sync_client", return_value=c),
            patch.object(mod, "datetime") as mock_dt,
        ):
            mock_dt.now.return_value.timestamp.return_value = 1000
            mock_dt.UTC = MagicMock()
            blacklist_token_sync("jti-sync-1", 1100)
            c.setex.assert_called_once_with(f"{_KEY_PREFIX}jti-sync-1", 100, "1")

    def test_ttl_never_below_one_second(self):
        c = _sync_client()
        with (
            patch.object(mod, "_get_sync_client", return_value=c),
            patch.object(mod, "datetime") as mock_dt,
        ):
            mock_dt.now.return_value.timestamp.return_value = 2000
            mock_dt.UTC = MagicMock()
            blacklist_token_sync("jti-sync-1", 1500)  # exp already passed
            assert c.setex.call_args[0][1] == 1

    def test_redis_error_does_not_raise(self):
        c = _sync_client(exc=RuntimeError("redis down"))
        with patch.object(mod, "_get_sync_client", return_value=c):
            assert blacklist_token_sync("jti-sync-1", 1100) is None


class TestIsBlacklistedSync:
    def test_empty_jti_false(self):
        with patch.object(mod, "_get_sync_client") as g:
            assert is_blacklisted_sync("") is False
            g.assert_not_called()

    def test_no_client_fail_open(self):
        with patch.object(mod, "_get_sync_client", return_value=None):
            assert is_blacklisted_sync("j") is False

    def test_revoked_token_true(self):
        c = _sync_client(get_value="1")
        with patch.object(mod, "_get_sync_client", return_value=c):
            assert is_blacklisted_sync("j") is True

    def test_live_token_false(self):
        c = _sync_client(get_value=None)
        with patch.object(mod, "_get_sync_client", return_value=c):
            assert is_blacklisted_sync("j") is False

    def test_redis_error_fail_open(self):
        c = _sync_client(exc=RuntimeError("boom"))
        with patch.object(mod, "_get_sync_client", return_value=c):
            assert is_blacklisted_sync("j") is False


class TestRevokeAllUserSessions:
    @pytest.mark.asyncio
    async def test_no_client_noop(self):
        with patch.object(mod, "_get_client", return_value=None):
            await revoke_all_user_sessions("u-1")

    @pytest.mark.asyncio
    async def test_sets_user_revoked_marker(self):
        c = AsyncMock()
        with (
            patch.object(mod, "_get_client", return_value=c),
            patch.object(mod, "datetime") as mock_dt,
        ):
            mock_dt.now.return_value.timestamp.return_value = 1000
            mock_dt.UTC = MagicMock()
            await revoke_all_user_sessions("u-1")
            args = c.setex.call_args[0]
            assert args[0] == f"{_KEY_PREFIX}user-revoked:u-1"
            # TTL covers the maximum access-token lifetime (JWT_EXPIRE_HOURS)
            assert args[1] >= 3600
            assert args[2] == "1000"

    @pytest.mark.asyncio
    async def test_redis_error_does_not_raise(self):
        c = AsyncMock()
        c.setex.side_effect = RuntimeError("redis down")
        with patch.object(mod, "_get_client", return_value=c):
            await revoke_all_user_sessions("u-1")


class TestUserSessionsRevoked:
    @pytest.mark.asyncio
    async def test_empty_args_false(self):
        assert await user_sessions_revoked("", 100) is False
        assert await user_sessions_revoked("u-1", 0) is False

    @pytest.mark.asyncio
    async def test_no_client_false(self):
        with patch.object(mod, "_get_client", return_value=None):
            assert await user_sessions_revoked("u-1", 100) is False

    @pytest.mark.asyncio
    async def test_token_older_than_revocation_true(self):
        c = AsyncMock()
        c.get.return_value = "2000"
        with patch.object(mod, "_get_client", return_value=c):
            assert await user_sessions_revoked("u-1", 1000) is True

    @pytest.mark.asyncio
    async def test_token_newer_than_revocation_false(self):
        c = AsyncMock()
        c.get.return_value = "500"
        with patch.object(mod, "_get_client", return_value=c):
            assert await user_sessions_revoked("u-1", 1000) is False

    @pytest.mark.asyncio
    async def test_never_revoked_false(self):
        c = AsyncMock()
        c.get.return_value = None
        with patch.object(mod, "_get_client", return_value=c):
            assert await user_sessions_revoked("u-1", 1000) is False

    @pytest.mark.asyncio
    async def test_redis_error_fail_open(self):
        c = AsyncMock()
        c.get.side_effect = RuntimeError("boom")
        with patch.object(mod, "_get_client", return_value=c):
            assert await user_sessions_revoked("u-1", 1000) is False
