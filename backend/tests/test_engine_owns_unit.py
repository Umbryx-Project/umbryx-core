"""_engine_owns: uid-first ownership with the legacy username fallback
(mirrors routes._owns; the engine's copy is what run-visibility uses)."""

from types import SimpleNamespace

from app.routers.playbooks._engine import _engine_owns


def _pb(uid, created_by):
    return SimpleNamespace(created_by_uid=uid, created_by=created_by)


def _user(uid, username):
    return SimpleNamespace(id=uid, username=username)


def test_uid_match_owns():
    assert _engine_owns(_pb("u1", "old_name"), _user("u1", "renamed")) is True


def test_uid_mismatch_rejected_even_if_username_matches():
    # uid is authoritative once stamped — a renamed user keeps access,
    # a same-username different-id account does NOT get it
    assert _engine_owns(_pb("u2", "alice"), _user("u9", "alice")) is False


def test_legacy_row_username_fallback():
    assert _engine_owns(_pb(None, "legacy_name"), _user("u3", "legacy_name")) is True


def test_legacy_row_username_mismatch():
    assert _engine_owns(_pb(None, "legacy_name"), _user("u3", "someone_else")) is False
