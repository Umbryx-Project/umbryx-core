"""Tests for app.core.security — password hashing, JWT token creation."""

import pytest
from unittest.mock import MagicMock

from app.core.security import (
    gen_password,
    hash_password,
    verify_password,
    make_token,
    make_stream_token,
    decode_token,
    decode_access_token,
)


class TestGenPassword:
    def test_default_length(self):
        p = gen_password()
        assert len(p) == 12

    def test_custom_length(self):
        p = gen_password(20)
        assert len(p) == 20

    def test_alphanumeric(self):
        p = gen_password(100)
        assert p.isalnum()

    def test_unique(self):
        pw1, pw2 = gen_password(), gen_password()
        assert pw1 != pw2


class TestHashPassword:
    def test_hashes_differently(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2

    def test_hash_is_string(self):
        h = hash_password("test")
        assert isinstance(h, str)

    def test_empty_password(self):
        h = hash_password("")
        assert isinstance(h, str)


class TestVerifyPassword:
    def test_correct_password(self):
        h = hash_password("secret")
        assert verify_password("secret", h) is True

    def test_wrong_password(self):
        h = hash_password("secret")
        assert verify_password("wrong", h) is False

    def test_empty_password_against_hash(self):
        h = hash_password("")
        assert verify_password("", h) is True

    def test_none_hash_returns_false(self):
        # Regression: a nonexistent user has no hash to check. This must
        # still run a full bcrypt verify against the internal dummy hash
        # (not short-circuit) — see test_login_timing_parity below for the
        # actual side channel this closes.
        assert verify_password("anything", None) is False

    def test_empty_string_hash_returns_false(self):
        # OIDC-only accounts store password_hash="".
        assert verify_password("anything", "") is False

    def test_none_hash_pays_full_bcrypt_cost(self):
        # The whole point of the fix: verifying against a missing hash must
        # take roughly the same time as verifying against a real one, not
        # short-circuit. Compare against a real bcrypt verify rather than a
        # fixed wall-clock threshold, so this isn't flaky under CI load.
        import time

        h = hash_password("secret")
        t0 = time.perf_counter()
        verify_password("wrong-guess", h)
        real_verify_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        verify_password("wrong-guess", None)
        none_verify_s = time.perf_counter() - t0

        # None-hash verify should cost at least half of a real bcrypt
        # verify — a short-circuit would be ~1000x faster (microseconds vs
        # ~100ms), so this comfortably separates "still doing bcrypt work"
        # from "skipped it".
        assert none_verify_s > real_verify_s * 0.5


class TestMakeAndDecodeToken:
    def test_roundtrip(self):
        user = MagicMock()
        user.id = "usr12345"
        user.username = "admin"
        user.role = "admin"
        token = make_token(user)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == "usr12345"
        assert decoded["username"] == "admin"
        assert decoded["role"] == "admin"
        assert "exp" in decoded
        assert "jti" in decoded

    def test_invalid_token_returns_none(self):
        assert decode_token("invalid.token.here") is None

    def test_empty_token_returns_none(self):
        assert decode_token("") is None


class TestMakeStreamToken:
    # Regression: auth_stream_token previously imported a nonexistent
    # ..core.auth module and 500'd on every call (security retest,
    # 2026-09-03). make_stream_token replaces that ad-hoc jwt.encode call.
    def _user(self):
        return MagicMock(id="u1", username="alice", role="user")

    def test_roundtrip_shape(self):
        token = make_stream_token(self._user())
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == "u1"
        assert decoded["username"] == "alice"
        assert decoded["role"] == "user"
        assert decoded["type"] == "stream"
        assert "iat" in decoded
        assert "jti" in decoded

    def test_rejected_as_a_normal_access_token(self):
        # This is the actual security property main.py's auth_middleware
        # relies on: a stream token must never authenticate a normal
        # Authorization: Bearer request.
        token = make_stream_token(self._user())
        assert decode_access_token(token) is None

    def test_token_has_jti(self):
        user = MagicMock()
        user.id = "u1"
        user.username = "test"
        user.role = "user"
        token = make_token(user)
        decoded = decode_token(token)
        assert len(decoded["jti"]) == 32

    def test_different_users_different_tokens(self):
        u1 = MagicMock(id="u1", username="a", role="user")
        u2 = MagicMock(id="u2", username="b", role="admin")
        assert make_token(u1) != make_token(u2)
