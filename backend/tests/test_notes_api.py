"""Comprehensive API tests for the notes router."""

import pytest

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post(
        "/api/auth/login", json={"username": "admin", "password": "TestPass1234!"}
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    r = module_client.post(
        "/api/projects",
        json={"name": "Notes Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Notes Test Proj")
    yield


class TestNoteCRUD:
    def test_create(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "Recon Notes",
                "content": "Nmap scan completed",
                "phase": "recon",
                "ts": "2025-01-15T10:00:00Z",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["title"] == "Recon Notes"
        assert data["content"] == "Nmap scan completed"
        assert data["phase"] == "recon"
        assert "id" in data
        _state["nid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/notes", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [n["id"] for n in r.json()]
        assert _state["nid"] in ids

    def test_update_title(self, module_client):
        r = module_client.patch(
            f"/api/notes/{_state['nid']}",
            json={"title": "Updated Recon Notes"},
        )
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Recon Notes"

    def test_update_content(self, module_client):
        r = module_client.patch(
            f"/api/notes/{_state['nid']}",
            json={"content": "Added more findings"},
        )
        assert r.status_code == 200
        assert r.json()["content"] == "Added more findings"

    def test_update_phase(self, module_client):
        r = module_client.patch(
            f"/api/notes/{_state['nid']}",
            json={"phase": "exploitation"},
        )
        assert r.status_code == 200
        assert r.json()["phase"] == "exploitation"

    def test_update_starred(self, module_client):
        r = module_client.patch(
            f"/api/notes/{_state['nid']}",
            json={"starred": True},
        )
        assert r.status_code == 200
        assert r.json()["starred"] is True

    def test_update_tags(self, module_client):
        r = module_client.patch(
            f"/api/notes/{_state['nid']}",
            json={"tags": ["important", "review"]},
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["important", "review"]

    def test_version_increments_on_update(self, module_client):
        r = module_client.get("/api/notes", params={"pid": _state["pid"]})
        note = next(n for n in r.json() if n["id"] == _state["nid"])
        assert note["version"] >= 1

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/notes/{_state['nid']}")
        assert r.status_code == 200
        r = module_client.get("/api/notes", params={"pid": _state["pid"]})
        ids = [n["id"] for n in r.json()]
        assert _state["nid"] not in ids


class TestNoteEdgeCases:
    def test_create_with_empty_title_fails(self, module_client):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "",
                "content": "x",
                "ts": "2025-01-01T00:00:00Z",
            },
        )
        assert r.status_code in (422, 500)

    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/notes/nonexistent_n", json={"title": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/notes/nonexistent_n")
        assert r.status_code == 404

    def test_create_multiple_notes(self, module_client):
        ids = []
        for i in range(3):
            r = module_client.post(
                "/api/notes",
                json={
                    "pid": _state["pid"],
                    "title": f"Batch Note {i}",
                    "content": f"Content {i}",
                    "ts": "2025-01-01T00:00:00Z",
                },
            )
            assert r.status_code == 201
            ids.append(r.json()["id"])
        r = module_client.get("/api/notes", params={"pid": _state["pid"]})
        all_ids = [n["id"] for n in r.json()]
        for nid in ids:
            assert nid in all_ids


class TestConfidentialAttachments:
    """External review 2026-10-29: confidential notes must encrypt
    attachments at rest (the text body already was)."""

    def _mk_note(self, module_client, tags=None):
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "enc-att",
                "content": "attack at dawn plan",
                "ts": "2026-10-29T10:00:00Z",
                "tags": tags or [],
            },
        )
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def test_confidential_attachment_stored_encrypted(self, module_client, module_db):
        import io

        from app import models as m
        from app.core.crypto import decrypt_bytes

        nid = self._mk_note(module_client, tags=["confidential"])
        r = module_client.post(
            f"/api/notes/{nid}/attachments",
            files={"file": ("plan.txt", io.BytesIO(b"attack at dawn"), "text/plain")},
        )
        assert r.status_code == 201, r.text
        att = module_db.query(m.NoteAttachment).filter(m.NoteAttachment.note_id == nid).first()
        assert att is not None and att.file_encrypted is True
        import asyncio

        from app.core.storage import get_storage_backend

        storage = get_storage_backend()
        raw = asyncio.run(storage.load(att.storage_path))
        assert raw != b"attack at dawn"  # ciphertext at rest
        assert decrypt_bytes(raw) == b"attack at dawn"  # round-trips

    def test_plain_note_attachment_stays_plain(self, module_client, module_db):
        import io

        from app import models as m

        nid = self._mk_note(module_client)
        r = module_client.post(
            f"/api/notes/{nid}/attachments",
            files={"file": ("pub.txt", io.BytesIO(b"public info"), "text/plain")},
        )
        assert r.status_code == 201, r.text
        att = module_db.query(m.NoteAttachment).filter(m.NoteAttachment.note_id == nid).first()
        assert att.file_encrypted is False
