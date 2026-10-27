"""Multi-framework C2 ops dispatch — Mythic and Sliver backends."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id
from app.models import GlobalSetting

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _integration(db, ftype: str, extra: dict | None = None):
    item = db.query(GlobalSetting).filter(GlobalSetting.key == "c2_integrations").first()
    value = item.value if item and isinstance(item.value, list) else []
    cfg = {
        "id": new_id("c2"),
        "name": f"{ftype}-ops-test",
        "type": ftype,
        "url": "https://203.0.113.70:443",
        "username": "admin",
        "password": "plainpwd",
        "enabled": True,
        "project_ids": [],
        **(extra or {}),
    }
    value.append(cfg)
    if item:
        item.value = value
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(item, "value")
    else:
        db.add(GlobalSetting(key="c2_integrations", value=value))
    db.commit()
    return cfg


class TestMythic:
    def test_list_listeners_maps_c2_profiles(self, module_client, module_db):
        from app.core.c2ops import mythic as c2_ops_mythic

        cfg = _integration(module_db, "mythic")
        with (
            patch.object(c2_ops_mythic, "_auth_headers", return_value={"apitoken": "t"}),
            patch.object(c2_ops_mythic.httpx, "Client") as MC,
        ):
            inst = MagicMock()
            resp = MagicMock(status_code=200)
            resp.json.return_value = {"data": {"c2profile": [{"name": "http", "id": "1"}, {"name": "smb", "id": "2"}]}}
            inst.post.return_value = resp
            MC.return_value.__enter__.return_value = inst
            out = c2_ops_mythic.list_listeners(cfg)
        assert [x["l_name"] for x in out] == ["http", "smb"]
        assert all(x["l_status"] == "available" for x in out)

    def test_create_listener_501_explains_model(self, module_client, module_db):
        from fastapi import HTTPException

        from app.core.c2ops import mythic as c2_ops_mythic

        cfg = _integration(module_db, "mythic")
        with pytest.raises(HTTPException) as e:
            c2_ops_mythic.create_listener(cfg, {"name": "x", "port": 1})
        assert e.value.status_code == 501
        assert "no standalone listeners" in e.value.detail

    def test_generate_payload_full_mutation_chain(self, module_client, module_db):
        from app.core.c2ops import mythic as c2_ops_mythic

        cfg = _integration(module_db, "mythic")
        calls = []

        def fake_gql(_cfg, _client, _h, query, variables=None):
            calls.append((query.split("(")[0].strip(), variables))
            if "createPayload" in query:
                return {"createPayload": {"uuid": "u42", "status": "created"}}
            if "payload(where" in query:
                return {"payload": [{"build_phase": "success", "build_message": "",
                                     "filemetum": {"agent_file_id": "f1", "filename": "x.exe"}}]}
            raise AssertionError(query)

        with (
            patch.object(c2_ops_mythic, "_auth_headers", return_value={"apitoken": "t"}),
            patch.object(c2_ops_mythic, "_gql", side_effect=fake_gql),
            patch.object(c2_ops_mythic.httpx, "Client") as MC,
        ):
            inst = MagicMock()
            dl = MagicMock(status_code=200, content=b"MZmythicpayload")
            inst.get.return_value = dl
            MC.return_value.__enter__.return_value = inst
            out = c2_ops_mythic.generate_payload(
                cfg, {"listener": "http", "agent": "apollo", "config": {}}
            )
        assert out["ok"] is True
        assert out["payload"] == b"MZmythicpayload"
        import json as _j
        assert _j.loads(calls[0][1]["pd"])["payload_type"] == "apollo"
        assert _j.loads(calls[0][1]["pd"])["c2_profiles"][0]["c2_profile"] == "http"


class TestSliver:
    def test_format_mapping(self):
        from app.core.c2ops.sliver import _FORMAT_MAP

        assert _FORMAT_MAP["DLL"] == "SHARED_LIB"

    def test_dispatch_routes_to_sliver(self, module_client, module_db):
        from app.core.c2ops.ops import ops_list_listeners

        cfg = _integration(module_db, "sliver", {"config": "{}"})
        from types import SimpleNamespace

        job = SimpleNamespace(Name="mtls", ID=7, Port=8888)
        jobs_resp = [job]
        with patch("app.core.c2ops.sliver._connected", new=AsyncMock(return_value=MagicMock(jobs=AsyncMock(return_value=jobs_resp)))):
            out = asyncio.run(ops_list_listeners(None, cfg))
        assert out[0]["l_name"] == "mtls-7"
        assert out[0]["l_bind_port"] == "8888"

    def test_dispatch_routes_to_mythic_and_adaptix(self, module_client, module_db):
        from app.core.c2ops.ops import ops_list_listeners

        mcfg = _integration(module_db, "mythic")
        with (
            patch("app.core.c2ops.mythic.list_listeners", return_value=[{"l_name": "http"}]) as mm,
        ):
            out = asyncio.run(ops_list_listeners(None, mcfg))
        assert out == [{"l_name": "http"}]
        mm.assert_called_once()

        acfg = _integration(module_db, "adaptix")
        with patch("app.core.c2ops.ops.list_listeners", return_value=[{"l_name": "ops"}]) as am:
            out = asyncio.run(ops_list_listeners(None, acfg))
        assert out == [{"l_name": "ops"}]
        am.assert_called_once()

    def test_api_accepts_all_three_types(self, module_client, module_db):
        mcfg = _integration(module_db, "mythic")
        r = module_client.get(f"/api/infra-v2/c2/{mcfg['id']}/listeners")
        # C2 unreachable -> 502, but NOT 404 (integration type accepted)
        assert r.status_code in (502, 200)
        scfg = _integration(module_db, "sliver", {"config": "{}"})
        r = module_client.get(f"/api/infra-v2/c2/{scfg['id']}/listeners")
        assert r.status_code in (502, 200)
