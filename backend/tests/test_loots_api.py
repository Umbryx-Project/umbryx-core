"""Comprehensive API tests for the loots router."""

import pytest
from fastapi.testclient import TestClient

from app import models

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
        json={"name": "Loots Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Loots Test Proj")
    yield


class TestLootCRUD:
    def test_create_hash_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "hash",
                "value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "description": "NTLM hash",
                "artifact_type": "hash",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["loot_type"] == "hash"
        assert data["artifact_type"] == "hash"
        assert "id" in data
        assert "ts" in data
        _state["lid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [l["id"] for l in r.json()]
        assert _state["lid"] in ids

    def test_update_description(self, module_client):
        r = module_client.patch(
            f"/api/loots/{_state['lid']}",
            json={"description": "Updated NTLM hash description"},
        )
        assert r.status_code == 200
        assert r.json()["description"] == "Updated NTLM hash description"

    def test_update_tags(self, module_client):
        r = module_client.patch(
            f"/api/loots/{_state['lid']}",
            json={"tags": ["cracked", "admin"]},
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["cracked", "admin"]

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/loots/{_state['lid']}")
        assert r.status_code == 200
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        ids = [l["id"] for l in r.json()]
        assert _state["lid"] not in ids


class TestLootTypes:
    def test_create_file_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "file",
                "value": "secret.txt",
                "description": "Extracted secrets file",
                "artifact_type": "file",
            },
        )
        assert r.status_code == 201
        assert r.json()["loot_type"] == "file"

    def test_create_text_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "text",
                "value": "password=P@ssw0rd",
                "description": "Config file content",
                "artifact_type": "text",
            },
        )
        assert r.status_code == 201
        assert r.json()["loot_type"] == "text"
        _state["lid2"] = r.json()["id"]

    def test_create_credential_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "credential",
                "value": "admin:Password123",
                "description": "Creds from memory",
                "artifact_type": "credential",
            },
        )
        assert r.status_code == 201
        assert r.json()["loot_type"] == "credential"


class TestLootFilters:
    def test_filter_by_artifact_type(self, module_client):
        r = module_client.get(
            "/api/loots",
            params={"pid": _state["pid"], "artifact_type": "text"},
        )
        assert r.status_code == 200
        for item in r.json():
            assert item["artifact_type"] == "text"

    def test_filter_by_host_id(self, module_client):
        r = module_client.get(
            "/api/loots",
            params={"pid": _state["pid"], "host_id": "nonexistent"},
        )
        assert r.status_code == 200
        assert len(r.json()) == 0


class TestLootEdgeCases:
    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/loots/nonexistent_lt", json={"description": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/loots/nonexistent_lt")
        assert r.status_code == 404

    def test_create_with_host_id(self, module_client):
        r_host = module_client.post(
            "/api/hosts",
            json={"pid": _state["pid"], "ip": "10.0.0.77"},
        )
        host_id = r_host.json()["id"]
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "host_id": host_id,
                "loot_type": "text",
                "value": "found on host",
                "artifact_type": "text",
            },
        )
        assert r.status_code == 201
        assert r.json()["host_id"] == host_id


class TestLootAuditTimelineDoesNotLeakSecret:
    """Regression for the 2026-08-29 audit finding: create/delete used to
    decrypt the loot value into the plaintext audit-timeline label."""

    def test_create_and_delete_do_not_leak_secret_in_timeline(self, module_client):
        secret_value = "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "hash",
                "value": secret_value,
                "artifact_type": "hash",
            },
        )
        assert r.status_code == 201, r.text
        lid = r.json()["id"]

        r = module_client.delete(f"/api/loots/{lid}")
        assert r.status_code in (200, 204), r.text

        r = module_client.get("/api/timeline", params={"pid": _state["pid"], "entity": "loot"})
        assert r.status_code == 200, r.text
        labels = " ".join(e["label"] for e in r.json())
        assert secret_value not in labels
        assert secret_value.split(":")[1] not in labels


class TestLootContentSearch:
    """FT: uploaded document content is searchable.

    The upload stores extracted_text; search matches against it. The
    HTTP endpoint uses Postgres full-text (to_tsvector/@@) which the sqlite
    test DB can't run — the existing search tests tolerate that with
    `status_code in (200, 500)` — so here we assert the real inclusion of
    extracted_text via the ILIKE branch of _search_loots, which runs
    everywhere and mirrors the fields the FTS vector now covers.
    """

    def test_uploaded_file_content_is_extracted_and_matched(self, module_client, module_db):
        r = module_client.post(
            "/api/loots",
            json={"pid": _state["pid"], "loot_type": "file", "value": "dump.txt", "artifact_type": "file"},
        )
        assert r.status_code == 201, r.text
        lid = r.json()["id"]

        marker = "zxqmarker7788 confidential kerberoast ticket"
        r = module_client.post(
            f"/api/loots/{lid}/file",
            files={"file": ("dump.txt", marker.encode(), "text/plain")},
        )
        assert r.status_code == 201, r.text

        # Content was extracted onto the row.
        from app import models

        loot = module_db.get(models.Loot, lid)
        module_db.refresh(loot)
        assert "kerberoast" in (loot.extracted_text or "")

        # ILIKE search branch (DB-agnostic) finds it by document content.
        from app.routers import search as S

        rows = S._search_loots(module_db, None, _state["pid"], False, "zxqmarker7788", "%zxqmarker7788%", 80)
        assert any(x["id"] == lid for x in rows), "loot not found by document content"


class TestLootListSurvivesUndecryptableValues:
    """Regression (found live): a rotated/lost ENCRYPTION_KEY made
    GET /api/loots 500 on the first undecryptable row — the whole loot
    list bricked instead of degrading per-row."""

    def test_list_returns_marker_for_undecryptable_value(self, module_client, module_db):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "cred",
                "artifact_type": "hash",
                "value": "supersecret-value",
                "description": "loot with a broken ciphertext",
            },
        )
        assert r.status_code in (200, 201), r.text
        loot_id = r.json()["id"]
        # simulate a value encrypted with a lost/rotated key
        loot = module_db.query(models.Loot).filter(models.Loot.id == loot_id).first()
        loot.value = "__enc__:gAAAAABnotarealfernettoken_______________"
        module_db.commit()

        r = module_client.get(f"/api/loots?pid={_state['pid']}")
        assert r.status_code == 200, r.text
        row = next(x for x in r.json() if x["id"] == loot_id)
        assert "undecryptable" in row["value"]
        assert "supersecret" not in row["value"]
