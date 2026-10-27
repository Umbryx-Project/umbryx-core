"""
Security-focused tests for the firewall config upload router
(routers/firewall_configs.py) — size limits, unrecognized-format handling,
and secrets never leaking into API responses.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.core.firewall_parsers.cisco_ios import CiscoIOSParser
from app.core.firewall_enrich import parsed_config_to_safe_dict

ADMIN = "admin"  # pre-seeded by the module_db fixture (conftest.py)
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}

CISCO_CFG_WITH_SECRET = """
hostname EdgeRouter1
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.252
!
username admin privilege 15 password 7 0822455D0A16
!
"""


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "FWConfigSecTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestSizeLimit:
    def test_oversized_config_rejected_before_parsing(self, module_client):
        pid = _state["pid"]
        oversized = "! " + ("a" * (6 * 1024 * 1024))  # over the 5 MB cap
        r = module_client.post(
            f"/api/projects/{pid}/firewall-configs/detect",
            data={"raw_text": oversized},
        )
        # starlette>=1.3 rejects oversized form bodies at the framework layer
        # with 400 before our handler's explicit 413; either way the payload
        # never reaches the config parser — which is what this test guards.
        assert r.status_code in (400, 413)

    def test_within_limit_accepted(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(
            f"/api/projects/{pid}/firewall-configs/detect",
            data={"raw_text": "interface GigabitEthernet0/0\n ip address 1.2.3.4 255.255.255.0\n"},
        )
        assert r.status_code == 200
        assert r.json()["vendor"] == "cisco_ios"


class TestUnrecognizedFormat:
    def test_detect_rejects_unknown_format(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(
            f"/api/projects/{pid}/firewall-configs/detect",
            data={"raw_text": "this is not any known firewall config syntax"},
        )
        assert r.status_code == 422

    def test_preview_rejects_unknown_format_without_side_effects(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(
            f"/api/projects/{pid}/firewall-configs/preview",
            data={"raw_text": "completely unrecognized gibberish config format xyz"},
        )
        assert r.status_code == 422

    def test_empty_body_rejected(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/firewall-configs/detect", data={})
        assert r.status_code == 400


class TestPreviewNeverLeaksSecrets:
    def test_preview_response_has_no_recoverable_secret(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(
            f"/api/projects/{pid}/firewall-configs/preview",
            data={"raw_text": CISCO_CFG_WITH_SECRET},
        )
        assert r.status_code == 200
        body = r.json()
        # "recoverable_secret"/"password"/"secret" keys must never appear
        # anywhere in the preview response — only aggregate counts.
        assert "recoverable_secret" not in body
        assert "password" not in str(body).lower()
        assert "secret" not in str(body).lower()
        assert body["planned"]["creds_created"] == 1

    def test_preview_does_not_persist_any_objects(self, module_client: TestClient):
        pid = _state["pid"]
        before = module_client.get(f"/api/projects/{pid}/firewall-configs").json()
        module_client.post(
            f"/api/projects/{pid}/firewall-configs/preview",
            data={"raw_text": CISCO_CFG_WITH_SECRET},
        )
        after = module_client.get(f"/api/projects/{pid}/firewall-configs").json()
        assert before == after == []


class TestParsedConfigNeverContainsSecret:
    def test_parsed_config_to_safe_dict_strips_secret(self):
        parsed = CiscoIOSParser().parse(CISCO_CFG_WITH_SECRET)
        assert parsed.local_users[0].recoverable_secret == "cisco"  # parser itself still has it
        safe = parsed_config_to_safe_dict(parsed)
        assert safe["local_users"][0]["recoverable_secret"] is None
        assert all(u["recoverable_secret"] is None for u in safe["local_users"])


class TestApplyJobHandlerEndToEnd:
    """Directly exercises the queued job handler (core/job_runner.py::
    _run_fwconfig_job) the way test_core_job_runner.py exercises other
    handlers — bypassing the worker pool/event-loop timing that makes
    asserting on background job completion through the HTTP layer flaky."""

    @pytest.mark.asyncio
    async def test_raw_config_stored_encrypted_and_secret_goes_only_to_cred(self, db):
        from app import models
        from app.core.job_runner import _run_fwconfig_job
        from app.core.job_tracker import queue_job
        from app.core.secure_files import save_encrypted
        from app.core.storage import get_storage_backend
        from app.core.transport import CancellationToken
        from app.core.utils import new_id, ts_now

        pid = new_id("prj")
        db.add(models.Project(id=pid, name="FW Job Test", added="2024-01-01"))
        db.commit()

        raw = CISCO_CFG_WITH_SECRET.encode("utf-8")
        storage_key = await save_encrypted(pid, f"{new_id('fwcfg')}.cfg", raw)

        # The file on disk must not contain the plaintext config/secret.
        backend = get_storage_backend()
        on_disk = await backend.load(storage_key)
        assert on_disk is not None
        assert b"cisco" not in on_disk
        assert b"EdgeRouter1" not in on_disk

        upload = models.FirewallConfigUpload(
            id=new_id("fwc"), pid=pid, vendor="cisco_ios",
            storage_key=storage_key, uploaded_by="admin", ts=ts_now(),
        )
        db.add(upload)
        db.commit()

        job = queue_job(
            db, pid, "fwconfig", "Firewall config: cisco_ios",
            connector_key="fwconfig", operation="parse_apply",
            request_json={"upload_id": upload.id}, created_by="admin",
        )

        await _run_fwconfig_job(db, job, CancellationToken())

        db.refresh(job)
        assert job.status == "done"
        assert "recoverable_secret" not in job.result_json
        assert "password" not in str(job.result_json).lower()

        db.refresh(upload)
        assert upload.host_id is not None
        assert all(u["recoverable_secret"] is None for u in upload.parsed_json["local_users"])

        cred = (
            db.query(models.Cred)
            .filter(models.Cred.pid == pid, models.Cred.service == "firewall_config")
            .first()
        )
        assert cred is not None
        assert cred.secret != "cisco"  # stored encrypted, not plaintext
        assert cred.secret.startswith("__pdek__:")
