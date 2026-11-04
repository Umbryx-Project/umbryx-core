"""c2/_sync internals: entry-node resolution, session-edge upserts and
the project-scoped API surface (test-connection / sync / bofs /
agent-tasks) — the shared-code port made these lines new in CE's
SonarQube window; the tests are edition-agnostic.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post(
        "/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS}
    )  # NOSONAR
    assert (
        module_client.post(
            "/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS}
        ).status_code
        == 200
    )
    yield
    module_client.post("/api/auth/logout")


def _enabled_registry():
    reg = MagicMock()
    reg.get.return_value = MagicMock(enabled=True)
    return reg


def _set_integration(module_db, cfg):
    from app.models import GlobalSetting

    module_db.merge(GlobalSetting(key="c2_integrations", value=[cfg]))
    module_db.commit()


def _cfg(**kw):
    cfg = {
        "id": "it_sync_1",
        "name": "lab c2",
        "type": "adaptix",
        "url": "https://c2.example",
        "enabled": True,
        "project_ids": [],
    }
    cfg.update(kw)
    return cfg


class TestTestConnectionEndpoint:
    def test_unknown_integration_404(self, module_client):
        r = module_client.post("/api/c2/none/test")
        assert r.status_code == 404

    def test_disabled_integration_400(self, module_client, module_db):
        _set_integration(module_db, _cfg(enabled=False))
        with patch("app.routers.c2._integrations.registry", _enabled_registry()):
            r = module_client.post("/api/c2/it_sync_1/test")
        assert r.status_code == 400 and "disabled" in r.text

    def test_unsupported_type_400(self, module_client, module_db):
        _set_integration(module_db, _cfg(type="cobaltstrike"))
        with patch("app.routers.c2._integrations.registry", _enabled_registry()):
            r = module_client.post("/api/c2/it_sync_1/test")
        assert r.status_code == 400 and "Unsupported" in r.text

    def test_connector_error_mapped_to_400(self, module_client, module_db):
        import httpx

        _set_integration(module_db, _cfg())
        bad = AsyncMock(side_effect=httpx.ConnectError("refused"))
        with (
            patch("app.routers.c2._integrations.registry", _enabled_registry()),
            patch.dict("app.routers.c2._sync._CONNECTORS", {"adaptix": bad}),
        ):
            r = module_client.post("/api/c2/it_sync_1/test")
        assert r.status_code == 400 and "Connection failed" in r.text

    def test_happy_path_counts(self, module_client, module_db):
        _set_integration(module_db, _cfg())
        ok = AsyncMock(
            return_value={"hosts": [{"ip": "1.2.3.4"}], "creds": [{"u": "a"}, {"u": "b"}]}
        )
        with (
            patch("app.routers.c2._integrations.registry", _enabled_registry()),
            patch.dict("app.routers.c2._sync._CONNECTORS", {"adaptix": ok}),
        ):
            r = module_client.post("/api/c2/it_sync_1/test")
        assert r.status_code == 200, r.text
        assert r.json() == {"ok": True, "hosts_found": 1, "creds_found": 2}


class TestSyncToProjectEndpoint:
    def _project(self, module_db):
        from app.core.utils import new_id, ts_now
        from app.models import Project

        pid = new_id("prj")
        module_db.add(Project(id=pid, name=f"c2sync-{pid[:6]}", added=ts_now()))
        module_db.commit()
        return pid

    def test_unknown_project_404(self, module_client, module_db):
        _set_integration(module_db, _cfg())
        with patch("app.routers.c2._integrations.registry", _enabled_registry()):
            r = module_client.post("/api/c2/it_sync_1/sync/prj_missing")
        assert r.status_code == 404

    def test_sync_maps_connector_failure_to_400(self, module_client, module_db):
        import httpx

        from app.routers.c2 import _sync as sync_mod

        pid = self._project(module_db)
        _set_integration(module_db, _cfg(project_ids=[pid]))
        with (
            patch("app.routers.c2._integrations.registry", _enabled_registry()),
            patch.object(
                sync_mod, "_do_project_sync", AsyncMock(side_effect=httpx.ConnectError("down"))
            ),
        ):
            r = module_client.post(f"/api/c2/it_sync_1/sync/{pid}")
        assert r.status_code == 400 and "Connection failed" in r.text

    def test_sync_happy_path(self, module_client, module_db):
        from app.routers.c2 import _sync as sync_mod

        pid = self._project(module_db)
        _set_integration(module_db, _cfg(project_ids=[pid]))
        result = {"hosts_found": 1, "hosts_created": 1, "hosts_updated": 0, "creds_created": 0}
        with (
            patch("app.routers.c2._integrations.registry", _enabled_registry()),
            patch.object(sync_mod, "_do_project_sync", AsyncMock(return_value=result)) as dps,
        ):
            r = module_client.post(f"/api/c2/it_sync_1/sync/{pid}")
        assert r.status_code == 200, r.text
        assert r.json()["hosts_found"] == 1
        dps.assert_awaited_once()


class TestBofsAndAgentTasks:
    def _project(self, module_db):
        from app.core.utils import new_id, ts_now
        from app.models import Project

        pid = new_id("prj")
        module_db.add(Project(id=pid, name=f"bof-{pid[:6]}", added=ts_now()))
        module_db.commit()
        return pid

    def test_non_adaptix_returns_empty_list(self, module_client, module_db):
        pid = self._project(module_db)
        _set_integration(module_db, _cfg(type="sliver", project_ids=[pid]))
        with patch("app.routers.c2._integrations.registry", _enabled_registry()):
            r = module_client.get(f"/api/c2/it_sync_1/bofs/{pid}")
        assert r.status_code == 200 and r.json() == []

    def test_adaptix_catalog_served(self, module_client, module_db):
        from app.routers.c2 import _sync as sync_mod

        pid = self._project(module_db)
        _set_integration(module_db, _cfg(project_ids=[pid]))
        with (
            patch("app.routers.c2._integrations.registry", _enabled_registry()),
            patch.object(
                sync_mod, "_adaptix_fetch_bof_catalog", AsyncMock(return_value=[{"name": "bof1"}])
            ),
        ):
            r = module_client.get(f"/api/c2/it_sync_1/bofs/{pid}")
        assert r.status_code == 200 and r.json() == [{"name": "bof1"}]

    def test_agent_tasks_missing_args_400(self, module_client, module_db):
        pid = self._project(module_db)
        with patch("app.routers.c2._integrations.registry", _enabled_registry()):
            r = module_client.get(f"/api/c2/agent-tasks/{pid}?integration_id=+&agent_id=")
        assert r.status_code == 400

    def test_agent_tasks_dispatches_by_type(self, module_client, module_db):
        from app.routers.c2 import _sync as sync_mod

        pid = self._project(module_db)
        _set_integration(module_db, _cfg(project_ids=[pid]))
        with (
            patch("app.routers.c2._integrations.registry", _enabled_registry()),
            patch.object(
                sync_mod, "_adaptix_fetch_agent_tasks", AsyncMock(return_value=[{"id": "t1"}])
            ) as fetch,
        ):
            r = module_client.get(
                f"/api/c2/agent-tasks/{pid}?integration_id=it_sync_1&agent_id=a1&limit=5"
            )
        assert r.status_code == 200 and r.json() == [{"id": "t1"}]
        # limit clamped into 1..100; cfg reloaded from storage (same id)
        args = fetch.await_args.args
        assert args[0]["id"] == "it_sync_1" and args[1] == "a1" and args[2] == 5

    def test_agent_tasks_unsupported_type_400(self, module_client, module_db):
        pid = self._project(module_db)
        _set_integration(module_db, _cfg(type="havoc", project_ids=[pid]))
        with patch("app.routers.c2._integrations.registry", _enabled_registry()):
            r = module_client.get(f"/api/c2/agent-tasks/{pid}?integration_id=it_sync_1&agent_id=a1")
        assert r.status_code == 400 and "not supported" in r.text


# ── graph internals ──────────────────────────────────────────────────
def _graph_fixture(module_db):
    """Project + attacker/target hosts + network graph with nodes."""
    from app.core.utils import new_id, ts_now
    from app.models import Host, Network, NetworkNode, Project

    pid = new_id("prj")
    module_db.add(Project(id=pid, name=f"graph-{pid[:6]}", added=ts_now()))
    module_db.commit()
    att = Host(id=new_id("h"), pid=pid, ip="203.0.113.10", is_attacker=True)
    tgt = Host(id=new_id("h"), pid=pid, ip="10.0.0.5")
    module_db.add_all([att, tgt])
    module_db.commit()
    net = Network(id=new_id("net"), pid=pid)
    module_db.add(net)
    module_db.commit()
    att_node = NetworkNode(
        id=new_id("nn"), network_id=net.id, pid=pid, ip=att.ip, host_id=att.id, is_attacker=True
    )
    tgt_node = NetworkNode(id=new_id("nn"), network_id=net.id, pid=pid, ip=tgt.ip, host_id=tgt.id)
    module_db.add_all([att_node, tgt_node])
    module_db.commit()
    return pid, net, att, tgt, att_node, tgt_node


class TestC2EntryNodeId:
    def test_no_service_id(self, module_db):
        from app.routers.c2._sync import _c2_entry_node_id

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        assert _c2_entry_node_id(module_db, pid, {}, []) is None

    def test_direct_entry_matched_by_attacker_host(self, module_db):
        from app.models.infra_v2 import InfraProvider, InfraStack, StackService
        from app.routers.c2._sync import _c2_entry_node_id

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        st = InfraStack(id="stk_en1", name="s", status="ready", created_at=ts_now())
        module_db.add(st)
        module_db.commit()
        svc = StackService(id="svc_en1", stack_id=st.id, role="c2", name="c2", status="running")
        module_db.add(svc)
        module_db.commit()
        prov = InfraProvider(
            id="pvp_en1", org_id=None, name="p", type="manual", host=att.ip, created_at=ts_now()
        )
        module_db.add(prov)
        module_db.commit()
        svc.provider_id = prov.id
        module_db.commit()

        cfg = {"service_id": svc.id}
        assert _c2_entry_node_id(module_db, pid, cfg, [att_node, tgt_node]) == att_node.id

    def test_redirector_tunnel_entry(self, module_db):
        from app.core.utils import ts_now as _ts
        from app.models.infra_v2 import InfraProvider, InfraStack, ServiceLink, StackService
        from app.routers.c2._sync import _c2_entry_node_id

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        st = InfraStack(id="stk_en2", name="s", status="ready", created_at=_ts())
        module_db.add(st)
        module_db.commit()
        c2 = StackService(id="svc_en2c", stack_id=st.id, role="c2", name="c2", status="running")
        rd = StackService(
            id="svc_en2r", stack_id=st.id, role="redirector", name="rd", status="running"
        )
        module_db.add_all([c2, rd])
        module_db.commit()
        prov = InfraProvider(
            id="pvp_en2", org_id=None, name="p", type="manual", host=att.ip, created_at=_ts()
        )
        module_db.add(prov)
        module_db.commit()
        rd.provider_id = prov.id
        module_db.commit()
        module_db.add(
            ServiceLink(
                id="lnk_en2",
                stack_id=st.id,
                from_service_id=rd.id,
                to_service_id=c2.id,
                link_type="reverse_tunnel",
                status="configured",
            )
        )
        module_db.commit()

        # the redirector (not the C2) is the public entry
        assert (
            _c2_entry_node_id(module_db, pid, {"service_id": c2.id}, [att_node, tgt_node])
            == att_node.id
        )


from app.core.utils import ts_now  # noqa: E402  (used above)


class TestUpsertSessionEdges:
    def test_live_session_edge_created_once_then_churn_free(self, module_db):
        from app.models import NetworkEdge
        from app.routers.c2._sync import _c2_upsert_session_edges

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        with patch("app.routers.c2._sync.bcast") as b:
            changed = _c2_upsert_session_edges(
                module_db, pid, "adaptix", ts_now(), {tgt.id}, set(), cfg=None
            )
            assert changed is True
            b.assert_called_once()  # broadcast only when the graph changed

            # second sync, same live set: creation-only semantics → no churn
            b.reset_mock()
            changed2 = _c2_upsert_session_edges(
                module_db, pid, "adaptix", ts_now(), {tgt.id}, set(), cfg=None
            )
            assert changed2 is False
            b.assert_not_called()

        edges = (
            module_db.query(NetworkEdge)
            .filter(NetworkEdge.network_id == net.id, NetworkEdge.type == "c2_session")
            .all()
        )
        assert len(edges) == 1
        assert edges[0].from_node_id == att_node.id
        assert edges[0].to_node_id == tgt_node.id

    def test_stale_session_edge_removed(self, module_db):
        from app.models import NetworkEdge
        from app.routers.c2._sync import _c2_upsert_session_edges

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        with patch("app.routers.c2._sync.bcast"):
            _c2_upsert_session_edges(module_db, pid, "adaptix", ts_now(), {tgt.id}, set(), cfg=None)
            changed = _c2_upsert_session_edges(
                module_db, pid, "adaptix", ts_now(), set(), {tgt.id}, cfg=None
            )
        assert changed is True
        remaining = (
            module_db.query(NetworkEdge)
            .filter(NetworkEdge.network_id == net.id, NetworkEdge.type == "c2_session")
            .count()
        )
        assert remaining == 0

    def test_no_network_is_silent_noop(self, module_db):
        from app.core.utils import new_id
        from app.core.utils import ts_now as _ts
        from app.models import Project
        from app.routers.c2._sync import _c2_upsert_session_edges

        pid = new_id("prj")
        module_db.add(Project(id=pid, name="no-net", added=_ts()))
        module_db.commit()
        assert _c2_upsert_session_edges(module_db, pid, "x", _ts(), {"h"}, set(), cfg=None) is None


class TestInfraEdgeAndCleanup:
    def _c2_stack(self, module_db, pid, c2_ip):
        from app.core.utils import ts_now as _ts
        from app.models.infra_v2 import InfraProvider, InfraStack, StackService

        st = InfraStack(id=f"stk_ie_{pid[:6]}", name="s", status="ready", created_at=_ts())
        module_db.add(st)
        module_db.commit()
        svc = StackService(
            id=f"svc_ie_{pid[:6]}", stack_id=st.id, role="c2", name="c2", status="running"
        )
        module_db.add(svc)
        module_db.commit()
        prov = InfraProvider(
            id=f"pvp_ie_{pid[:6]}",
            org_id=None,
            name="p",
            type="manual",
            host=c2_ip,
            created_at=_ts(),
        )
        module_db.add(prov)
        module_db.commit()
        svc.provider_id = prov.id
        module_db.commit()
        return svc

    def test_infra_edge_redirector_to_c2_host(self, module_db):
        """cfg.service_id with its own provider → c2_infra edge from the
        entry node to the C2 host node (the chain beacons traverse)."""
        from app.models import Host, NetworkEdge, NetworkNode
        from app.models.infra_v2 import InfraProvider, InfraStack, ServiceLink, StackService
        from app.routers.c2._sync import _c2_upsert_session_edges

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        # a SECOND attacker host plays the C2 machine (own node)
        from app.core.utils import new_id
        from app.core.utils import ts_now as _ts

        c2_host = Host(id=new_id("h"), pid=pid, ip="198.51.100.20", is_attacker=True)
        module_db.add(c2_host)
        module_db.commit()
        c2_node = NetworkNode(
            id=new_id("nn"),
            network_id=net.id,
            pid=pid,
            ip=c2_host.ip,
            host_id=c2_host.id,
            is_attacker=True,
        )
        module_db.add(c2_node)
        module_db.commit()
        svc = self._c2_stack(module_db, pid, c2_host.ip)

        # reverse tunnel: redirector (on att.ip) fronts the C2 — the
        # beacons' public entry is the REDIRECTOR, not the C2 host
        st = module_db.query(InfraStack).filter(InfraStack.id == svc.stack_id).first()
        from app.core.utils import new_id as _nid

        rd = StackService(
            id=_nid("svc"), stack_id=st.id, role="redirector", name="rd", status="running"
        )
        module_db.add(rd)
        module_db.commit()
        rd_prov = InfraProvider(
            id=_nid("pvp"), org_id=None, name="rd", type="manual", host=att.ip, created_at=_ts()
        )
        module_db.add(rd_prov)
        module_db.commit()
        rd.provider_id = rd_prov.id
        module_db.commit()
        module_db.add(
            ServiceLink(
                id=_nid("lnk"),
                stack_id=st.id,
                from_service_id=rd.id,
                to_service_id=svc.id,
                link_type="reverse_tunnel",
                status="configured",
            )
        )
        module_db.commit()

        cfg = {"service_id": svc.id}
        with patch("app.routers.c2._sync.bcast"):
            changed = _c2_upsert_session_edges(
                module_db, pid, "adaptix", _ts(), {tgt.id}, set(), cfg=cfg
            )
        assert changed is True
        infra = (
            module_db.query(NetworkEdge)
            .filter(NetworkEdge.network_id == net.id, NetworkEdge.type == "c2_infra")
            .all()
        )
        assert len(infra) == 1
        assert infra[0].from_node_id == att_node.id  # the redirector's node = entry
        assert infra[0].to_node_id == c2_node.id

    def test_infra_edge_ip_fallback_and_no_churn(self, module_db):
        """C2 host not registered as a Host → node matched by ip; a second
        sync must not rewrite the edge (creation-only, no churn)."""
        from app.models import NetworkNode
        from app.routers.c2._sync import _c2_upsert_session_edges

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        from app.core.utils import new_id
        from app.core.utils import ts_now as _ts

        c2_node = NetworkNode(
            id=new_id("nn"), network_id=net.id, pid=pid, ip="198.51.100.21", is_attacker=True
        )
        module_db.add(c2_node)
        module_db.commit()
        svc = self._c2_stack(module_db, pid, c2_node.ip)

        with patch("app.routers.c2._sync.bcast") as b:
            _c2_upsert_session_edges(
                module_db, pid, "adaptix", _ts(), set(), set(), cfg={"service_id": svc.id}
            )
            b.reset_mock()
            changed = _c2_upsert_session_edges(
                module_db, pid, "adaptix", _ts(), set(), set(), cfg={"service_id": svc.id}
            )
        assert changed is False
        b.assert_not_called()

    def test_wrong_from_node_edges_cleaned_up(self, module_db):
        """Session edges written earlier from a DIFFERENT attacker node are
        dropped on the next sync (the arbitrary-attacker-node bug)."""
        from app.core.utils import new_id, stable_edge_id
        from app.core.utils import ts_now as _ts
        from app.models import NetworkEdge, NetworkNode
        from app.routers.c2._sync import _c2_upsert_session_edges

        pid, net, att, tgt, att_node, tgt_node = _graph_fixture(module_db)
        other_att = NetworkNode(
            id=new_id("nn"), network_id=net.id, pid=pid, ip="203.0.113.99", is_attacker=True
        )
        module_db.add(other_att)
        module_db.commit()
        stale_id = stable_edge_id(other_att.id, tgt_node.id, "c2_sync", "c2_session")
        module_db.add(
            NetworkEdge(
                id=stale_id,
                network_id=net.id,
                pid=pid,
                from_node_id=other_att.id,
                to_node_id=tgt_node.id,
                type="c2_session",
                source="c2_sync",
                confidence=1.0,
            )
        )
        module_db.commit()

        with patch("app.routers.c2._sync.bcast"):
            changed = _c2_upsert_session_edges(
                module_db, pid, "adaptix", _ts(), {tgt.id}, set(), cfg=None
            )
        assert changed is True
        assert module_db.query(NetworkEdge).filter(NetworkEdge.id == stale_id).first() is None
        # the correct edge exists from the real attacker node
        good_id = stable_edge_id(att_node.id, tgt_node.id, "c2_sync", "c2_session")
        assert module_db.query(NetworkEdge).filter(NetworkEdge.id == good_id).first() is not None
