"""Purple-team view — cross-source MITRE aggregation (steps + tagged edges)
with defender timeline and finding severity stats."""

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.models import AttackPath, AttackStep, Network, NetworkEdge

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _mk_project(client):
    r = client.post(
        "/api/projects", json={"name": f"Purple{new_id('p')[:6]}", "added": "2025-01-01T00:00:00Z"}
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


class TestPurpleView:
    def test_aggregates_steps_and_edges(self, module_client, module_db):
        pid = _mk_project(module_client)

        # attack path step with a technique
        path = AttackPath(pid=pid, id=new_id("ap"), name="p", ts=ts_now())
        module_db.add(path)
        module_db.flush()
        module_db.add(
            AttackStep(
                pid=pid,
                path_id=path.id,
                id=new_id("step"),
                label="Pass-the-hash to DC",
                technique="Pass the Hash",
                mitre_id="T1550.002",
                step_order=1,
                ts=ts_now(),
            )
        )

        # tagged graph edge (Smart Build SB4 style)
        net = Network(pid=pid, id=new_id("net"), name="n")
        module_db.add(net)
        module_db.flush()
        module_db.add(
            NetworkEdge(
                pid=pid,
                network_id=net.id,
                id=new_id("edge"),
                from_node_id="a",
                to_node_id="b",
                label="cred validation",
                source="cred_validation",
                extra_json={"mitre_techniques": ["T1550.002", "T1021"]},
            )
        )
        module_db.commit()

        r = module_client.get(f"/api/projects/{pid}/purple")
        assert r.status_code == 200
        body = r.json()

        by_id = {t["id"]: t for t in body["techniques"]}
        assert "T1550.002" in by_id
        assert by_id["T1550.002"]["steps"] == 1
        assert by_id["T1550.002"]["edges"] == 1, "same technique from two sources merges"
        assert "T1021" in by_id
        assert by_id["T1021"]["edges"] == 1

        stats = body["stats"]
        assert stats["techniques_total"] == 2
        assert stats["steps_with_mitre"] == 1
        assert stats["tagged_edges"] == 1

    def test_empty_project_shape(self, module_client):
        pid = _mk_project(module_client)
        r = module_client.get(f"/api/projects/{pid}/purple")
        assert r.status_code == 200
        body = r.json()
        assert body["techniques"] == []
        assert body["stats"]["techniques_total"] == 0
        assert body["timeline"] == [] or all(t["entity"] == "project" for t in body["timeline"])
        assert isinstance(body["tactic_order"], list) and "Lateral Movement" in body["tactic_order"]

    def test_timeline_included_desc(self, module_client, module_db):
        pid = _mk_project(module_client)
        from app.core.events import log_event

        log_event(module_db, pid, "alice", "host", "create", "Host 10.0.0.1 discovered", {})
        log_event(module_db, pid, "bob", "cred", "validate", "SMB cred valid", {})
        module_db.commit()

        r = module_client.get(f"/api/projects/{pid}/purple")
        timeline = r.json()["timeline"]
        assert len(timeline) >= 2
        assert timeline[0]["ts"] >= timeline[-1]["ts"], "newest first for the defender review"
