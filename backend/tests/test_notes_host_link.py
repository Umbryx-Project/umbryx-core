"""Notes <-> Host linking (Note.host_id) — see alembic/versions/074_note_host_link.py."""

import pytest

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"

    r = module_client.post(
        "/api/projects",
        json={"name": "NoteHostLink Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]

    r = module_client.post(
        "/api/hosts",
        json={"pid": _state["pid"], "ip": "10.9.9.1", "hostname": "linktest01"},
    )
    assert r.status_code == 201, r.text
    _state["hid"] = r.json()["id"]

    r = module_client.post(
        "/api/projects",
        json={"name": "NoteHostLink Other", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code == 201, r.text
    _state["other_pid"] = r.json()["id"]
    yield


class TestCreateWithHost:
    def test_create_with_host_id(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "Host note",
                "content": "found stuff",
                "ts": "2025-01-01 00:00",
                "host_id": _state["hid"],
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["host_id"] == _state["hid"]
        _state["note_id"] = data["id"]

    def test_create_without_host_id_stays_unattached(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "Project-level note",
                "ts": "2025-01-01 00:00",
            },
        )
        assert r.status_code == 201, r.text
        assert r.json()["host_id"] is None

    def test_create_with_host_from_other_project_rejected(self, module_client):
        r = module_client.post(
            "/api/hosts",
            json={"pid": _state["other_pid"], "ip": "10.9.9.2", "hostname": "otherhost"},
        )
        assert r.status_code == 201, r.text
        other_hid = r.json()["id"]

        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "Cross-project attempt",
                "ts": "2025-01-01 00:00",
                "host_id": other_hid,
            },
        )
        assert r.status_code == 404, r.text

    def test_create_with_nonexistent_host_rejected(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "Bad host",
                "ts": "2025-01-01 00:00",
                "host_id": "hst_does_not_exist",
            },
        )
        assert r.status_code == 404, r.text


class TestUpdateHostLink:
    def test_attach_existing_note_to_host(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={"pid": _state["pid"], "title": "Attach me later", "ts": "2025-01-01 00:00"},
        )
        assert r.status_code == 201, r.text
        nid = r.json()["id"]
        assert r.json()["host_id"] is None

        r = module_client.patch(f"/api/notes/{nid}", json={"host_id": _state["hid"]})
        assert r.status_code == 200, r.text
        assert r.json()["host_id"] == _state["hid"]

    def test_unlink_host_via_explicit_null(self, module_client):
        nid = _state["note_id"]
        r = module_client.patch(f"/api/notes/{nid}", json={"host_id": None})
        assert r.status_code == 200, r.text
        assert r.json()["host_id"] is None

    def test_update_without_host_id_field_leaves_link_untouched(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"], "title": "Stays linked", "ts": "2025-01-01 00:00",
                "host_id": _state["hid"],
            },
        )
        nid = r.json()["id"]
        r = module_client.patch(f"/api/notes/{nid}", json={"content": "edited body only"})
        assert r.status_code == 200, r.text
        assert r.json()["host_id"] == _state["hid"]
        assert r.json()["content"] == "edited body only"

    def test_attach_to_host_in_other_project_rejected(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={"pid": _state["pid"], "title": "n", "ts": "2025-01-01 00:00"},
        )
        nid = r.json()["id"]
        r = module_client.post(
            "/api/hosts",
            json={"pid": _state["other_pid"], "ip": "10.9.9.3", "hostname": "other2"},
        )
        other_hid = r.json()["id"]
        r = module_client.patch(f"/api/notes/{nid}", json={"host_id": other_hid})
        assert r.status_code == 404, r.text


class TestHostCardNotesVisibility:
    def test_notes_endpoint_filters_by_host_via_client(self, module_client):
        r = module_client.get(f"/api/notes?pid={_state['pid']}")
        assert r.status_code == 200, r.text
        notes = r.json()
        host_notes = [n for n in notes if n.get("host_id") == _state["hid"]]
        assert len(host_notes) >= 1


class TestListOrdering:
    """GET /api/notes has an explicit ORDER BY (ts desc, id desc) — without
    it Postgres doesn't guarantee stable row order across calls with
    LIMIT/OFFSET, which could bury a just-created note past the default
    page size on a project with many notes. See routers/notes.py."""

    def test_list_is_ordered_by_ts_desc(self, module_client):
        pid = _state["pid"]
        module_client.post(
            "/api/notes",
            json={"pid": pid, "title": "Earliest", "ts": "2020-01-01 00:00"},
        )
        module_client.post(
            "/api/notes",
            json={"pid": pid, "title": "Latest", "ts": "2030-01-01 00:00"},
        )
        r = module_client.get(f"/api/notes?pid={pid}")
        assert r.status_code == 200, r.text
        notes = r.json()
        ts_values = [n["ts"] for n in notes]
        assert ts_values == sorted(ts_values, reverse=True)
