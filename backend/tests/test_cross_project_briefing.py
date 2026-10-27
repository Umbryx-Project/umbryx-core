"""AI tool: cross_project_briefing — read-only summary across all of a user's projects."""

from fastapi.testclient import TestClient

from app.core.ai_tools import tool_cross_project_briefing
from app.core.utils import new_id, ts_now
from app.models import AttackPath, AttackStep, Finding, Objective, User

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


def _bootstrap(client: TestClient):
    client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200


def _make_project(client, name):
    r = client.post("/api/projects", json={"name": name, "added": "2025-01-01T00:00:00Z"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


class TestCrossProjectBriefing:
    def test_no_user_returns_error(self, client, db):
        _bootstrap(client)
        result = tool_cross_project_briefing(db, pid="irrelevant", user_id=None)
        assert "error" in result

    def test_unknown_user_returns_error(self, client, db):
        _bootstrap(client)
        result = tool_cross_project_briefing(db, pid="irrelevant", user_id="nonexistent-user-id")
        assert "error" in result

    def test_aggregates_across_projects(self, client, db):
        _bootstrap(client)
        user = db.query(User).filter(User.username == ADMIN).first()

        pid_a = _make_project(client, f"BriefA-{new_id('p')[:6]}")
        pid_b = _make_project(client, f"BriefB-{new_id('p')[:6]}")

        # Project A: mostly done — 2/2 objectives, 1 verified step, no open findings.
        db.add(Objective(id=new_id("obj"), pid=pid_a, title="Flag 1", status="captured", ts=ts_now()))
        db.add(Objective(id=new_id("obj"), pid=pid_a, title="Flag 2", status="submitted", ts=ts_now()))
        path_a = AttackPath(id=new_id("path"), pid=pid_a, name="Path A", ts=ts_now())
        db.add(path_a)
        db.flush()
        db.add(AttackStep(id=new_id("step"), path_id=path_a.id, pid=pid_a, node_status="verified", ts=ts_now()))

        # Project B: early — 0/1 objectives, 2 untested hypotheses, 1 open finding.
        db.add(Objective(id=new_id("obj"), pid=pid_b, title="Flag 1", status="not_started", ts=ts_now()))
        path_b = AttackPath(id=new_id("path"), pid=pid_b, name="Path B", ts=ts_now())
        db.add(path_b)
        db.flush()
        db.add(AttackStep(id=new_id("step"), path_id=path_b.id, pid=pid_b, node_status="hypothetical", ts=ts_now()))
        db.add(AttackStep(id=new_id("step"), path_id=path_b.id, pid=pid_b, node_status="planned", ts=ts_now()))
        db.add(Finding(id=new_id("fnd"), pid=pid_b, title="Open one", severity="high", status="open", ts=ts_now()))
        db.commit()

        result = tool_cross_project_briefing(db, pid="irrelevant", user_id=user.id)
        by_id = {p["project_id"]: p for p in result["projects"]}

        assert by_id[pid_a]["objectives_total"] == 2
        assert by_id[pid_a]["objectives_done"] == 2
        assert by_id[pid_a]["attack_steps_verified"] == 1
        assert by_id[pid_a]["attack_steps_untested_hypotheses"] == 0
        assert by_id[pid_a]["open_findings"] == 0
        # project creation itself already logs a timeline event, so just
        # confirm the tool surfaces *some* last-activity timestamp rather
        # than pinning the exact value against auto-generated events.
        assert by_id[pid_a]["last_activity_ts"]

        assert by_id[pid_b]["objectives_total"] == 1
        assert by_id[pid_b]["objectives_done"] == 0
        assert by_id[pid_b]["attack_steps_untested_hypotheses"] == 2
        assert by_id[pid_b]["open_findings"] == 1

    def test_excludes_archived_by_default(self, client, db):
        _bootstrap(client)
        user = db.query(User).filter(User.username == ADMIN).first()
        pid = _make_project(client, f"Archived-{new_id('p')[:6]}")

        from app.models import Project

        proj = db.query(Project).filter(Project.id == pid).first()
        proj.archived_at = "2026-01-01T00:00:00Z"
        db.commit()

        result = tool_cross_project_briefing(db, pid="irrelevant", user_id=user.id)
        assert pid not in {p["project_id"] for p in result["projects"]}

        result_incl = tool_cross_project_briefing(db, pid="irrelevant", user_id=user.id, include_archived=True)
        assert pid in {p["project_id"] for p in result_incl["projects"]}
