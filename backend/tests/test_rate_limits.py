"""Regression tests: heavy operations (export, PDF/HTML report generation,
bulk-exec) had no rate limiting at all — only /api/auth/login did. 20
consecutive requests to GET /api/export/{pid} all returned 200 in a live
retest with no throttling whatsoever (security retest, 2026-09-03).

The rate limiter is disabled globally under APP_ENV=test (see
core/limiter.py and conftest.py), so these tests re-enable it for the
duration of a single test and reset its storage before/after — otherwise
leftover counters from one test would bleed into the next, and every other
test file in the suite would need @limiter.limit to stay dormant.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.limiter import limiter

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post(
        "/api/projects",
        json={"name": "RateLimitTestProj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), r.text
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "RateLimitTestProj")
    yield


@pytest.fixture
def _enabled_limiter():
    limiter.enabled = True
    limiter.reset()
    try:
        yield
    finally:
        limiter.reset()
        limiter.enabled = False


class TestExportRateLimit:
    def test_export_throttles_after_limit(self, module_client: TestClient, _enabled_limiter):
        pid = _state["pid"]
        statuses = [module_client.get(f"/api/export/{pid}").status_code for _ in range(15)]
        assert 429 in statuses, f"no 429 among 15 requests: {statuses}"
        # Everything up to the limit must still have worked normally.
        assert statuses[0] == 200


class TestReportRateLimit:
    def test_pdf_report_throttles_after_limit(self, module_client: TestClient, _enabled_limiter):
        pid = _state["pid"]
        statuses = [
            module_client.get(f"/api/projects/{pid}/report/pdf").status_code for _ in range(15)
        ]
        assert 429 in statuses, f"no 429 among 15 requests: {statuses}"

    def test_html_report_throttles_after_limit(self, module_client: TestClient, _enabled_limiter):
        pid = _state["pid"]
        statuses = [
            module_client.get(f"/api/projects/{pid}/report/html").status_code for _ in range(15)
        ]
        assert 429 in statuses, f"no 429 among 15 requests: {statuses}"


class TestBulkExecRateLimit:
    def test_bulk_exec_throttles_after_limit(self, module_client: TestClient, _enabled_limiter):
        pid = _state["pid"]
        # attacker_ssh is disabled by default in this env, so every one of
        # these 400s on _require_enabled() before it can hit the rate
        # limiter's own check... except @limiter.limit runs as a route
        # decorator, ahead of the function body, so it still throttles
        # regardless of what the handler would have done next.
        statuses = [
            module_client.post(
                f"/api/projects/{pid}/bulk-exec",
                json={"host_ids": ["h1"], "command_template": "id"},
            ).status_code
            for _ in range(15)
        ]
        assert 429 in statuses, f"no 429 among 15 requests: {statuses}"
