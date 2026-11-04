"""Guard: every _PUBLIC_PATHS entry must match a real route.

A review-2026-10-30 finding (A-4): `/api/infra-v2/services/heartbeat`
sat in _PUBLIC_PATHS long after its route was deleted — and because the
auth middleware matches by path prefix, ANY future route mounted under a
stale entry would inherit unauthenticated access silently.

This test fails the build whenever a public path stops matching at least
one registered route, so a dead entry can never outlive its endpoint.

Route discovery goes through the OpenAPI schema: the app uses FastAPI's
lazy router inclusion (_IncludedRouter), whose wrapper objects don't
expose plain `.path` attributes — while the OpenAPI document is exactly
the set of HTTP routes the outside world can reach.
"""

import pytest

from app.main import _PUBLIC_PATHS, app


@pytest.fixture(scope="module")
def registered_paths() -> set[str]:
    return set(app.openapi()["paths"].keys())


def test_every_public_path_matches_a_registered_route(registered_paths):
    # Middleware semantics: a request path is public if it STARTS WITH an
    # entry — so each entry must prefix at least one real route path.
    orphans = [p for p in _PUBLIC_PATHS if not any(r.startswith(p) for r in registered_paths)]
    assert not orphans, (
        f"_PUBLIC_PATHS entries with no matching route — these grant "
        f"unauthenticated access to any future route mounted under them: {orphans}"
    )
