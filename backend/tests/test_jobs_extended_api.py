"""Extended jobs API tests — get single job, output-stream, artifacts, filters."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.job_tracker import queue_job, finish_job

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "Jobs Extended", "added": "2025-01-01", "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestGetSingleJob:
    def test_get_existing_job(self, module_client: TestClient, module_db: Session):
        job = queue_job(module_db, _state["pid"], "nmap", "Get Job Test",
                        connector_key="nmap", operation="scan",
                        request_json={"target": "10.0.0.10"})
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs/{job.id}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == job.id
        assert data["title"] == "Get Job Test"

    def test_get_nonexistent_job_404(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs/job_nonexistent")
        assert r.status_code == 404


class TestJobOutputSearch:
    def test_output_search_filter(self, module_client: TestClient, module_db: Session):
        job = queue_job(module_db, _state["pid"], "nmap", "Output Search Test",
                        connector_key="nmap", operation="scan",
                        request_json={"target": "10.0.0.11"})
        finish_job(module_db, job, status="done", output="Host 10.0.0.11 is up")
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs?output_search=10.0.0.11")
        assert r.status_code == 200
        ids = [j["id"] for j in r.json()]
        assert job.id in ids

    def test_output_search_no_match(self, module_client: TestClient, module_db: Session):
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs?output_search=zzz_no_match_zzz")
        assert r.status_code == 200
        assert len(r.json()) == 0


class TestJobArtifacts:
    def test_artifacts_for_job(self, module_client: TestClient, module_db: Session):
        job = queue_job(module_db, _state["pid"], "nmap", "Artifacts Test",
                        connector_key="nmap", operation="scan",
                        request_json={"target": "10.0.0.12"})
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs/{job.id}/artifacts")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_artifacts_nonexistent_job_404(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs/job_nonexistent/artifacts")
        assert r.status_code == 404


class TestJobOutputStream:
    def test_output_stream_returns_events(self, module_client: TestClient, module_db: Session):
        job = queue_job(module_db, _state["pid"], "nmap", "Stream Test",
                        connector_key="nmap", operation="scan",
                        request_json={"target": "10.0.0.13"})
        finish_job(module_db, job, status="done", output="scan complete")
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs/{job.id}/output-stream")
        assert r.status_code == 200
        assert "text/event-stream" in r.headers.get("content-type", "")

    def test_output_stream_nonexistent_job_404(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs/job_nonexistent/output-stream")
        assert r.status_code == 404

    def test_output_stream_carries_ids(self, module_client: TestClient, module_db: Session):
        from app.core import job_streams
        job = queue_job(module_db, _state["pid"], "nmap", "IDs",
                        connector_key="nmap", operation="scan", request_json={"target": "10.0.0.14"})
        job_streams.init_stream(job.id)
        for ln in ("l1", "l2", "l3"):
            job_streams.push_line(job.id, ln)
        job_streams.close_stream(job.id)
        body = module_client.get(f"/api/projects/{_state['pid']}/jobs/{job.id}/output-stream").text
        assert "id: 1" in body and "id: 3" in body  # SSE ids for Last-Event-ID resume
        assert "l1" in body and "l3" in body and '"done": true' in body

    def test_output_stream_resumes_from_last_event_id(self, module_client: TestClient, module_db: Session):
        from app.core import job_streams
        job = queue_job(module_db, _state["pid"], "nmap", "Resume",
                        connector_key="nmap", operation="scan", request_json={"target": "10.0.0.15"})
        job_streams.init_stream(job.id)
        for ln in ("l1", "l2", "l3"):
            job_streams.push_line(job.id, ln)
        job_streams.close_stream(job.id)
        # Reconnect claiming 2 lines already seen -> only the third is replayed.
        body = module_client.get(
            f"/api/projects/{_state['pid']}/jobs/{job.id}/output-stream",
            headers={"Last-Event-ID": "2"},
        ).text
        assert "l3" in body
        assert "l1" not in body and "l2" not in body


class TestJobOffsetParam:
    def test_offset_param(self, module_client: TestClient, module_db: Session):
        for i in range(5):
            queue_job(module_db, _state["pid"], "nmap", f"Offset Job {i}",
                      connector_key="nmap", operation="scan",
                      request_json={"target": f"10.0.0.{20+i}"})
        r = module_client.get(f"/api/projects/{_state['pid']}/jobs?offset=3&limit=2")
        assert r.status_code == 200
        assert len(r.json()) <= 2
