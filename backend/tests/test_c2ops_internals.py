"""c2ops internals: the port-exposure, listener lifecycle and context
plumbing under the API layer.

Written for the CE new-coverage window (the shared-code port made these
lines new there) but valid for both editions: every EE seam
(ee_import / app.ee.infra.links) is patched or injected through
sys.modules so the tested paths are identical everywhere.
"""

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

import app.core.c2ops.ops as ops


def _client_mock(post_results=None, get_json=None):
    client = MagicMock()
    posts = list(post_results or [])
    client.post = MagicMock(side_effect=posts) if posts else MagicMock()
    if get_json is not None:
        client.get.return_value.json.return_value = get_json
    return client


class TestGetIntegration:
    def test_found_by_id(self, module_db):
        from app.models import GlobalSetting

        module_db.merge(GlobalSetting(key="c2_integrations", value=[{"id": "i1"}, {"id": "i2"}]))
        module_db.commit()
        assert ops.get_integration(module_db, "i2") == {"id": "i2"}

    def test_missing_id_and_non_list(self, module_db):
        from app.models import GlobalSetting

        module_db.merge(GlobalSetting(key="c2_integrations", value=[{"id": "i1"}]))
        module_db.commit()
        assert ops.get_integration(module_db, "nope") is None
        module_db.merge(GlobalSetting(key="c2_integrations", value="not-a-list"))
        module_db.commit()
        assert ops.get_integration(module_db, "i1") is None


class TestListenerTypeFor:
    @pytest.mark.parametrize(
        "requested,expected",
        [
            ("http", "BeaconHTTP"),
            ("HTTP", "BeaconHTTP"),
            ("tcp", "BeaconTCP"),
            ("something ransomware-ish", "BeaconHTTP"),  # default fallback
        ],
    )
    def test_mapping(self, requested, expected):
        assert ops._listener_type_for(requested) == expected


class TestLogin:
    def _cfg(self, **kw):
        cfg = {
            "url": "https://c2.example",
            "username": "u",
            "password": "p",
            "allow_private_network": True,  # skip the guard's live DNS check
        }
        cfg.update(kw)
        return cfg

    def test_login_flow_and_token(self):
        resp = MagicMock()
        resp.json.return_value = {"access_token": "tok123"}
        with patch.object(ops.httpx, "Client") as client_cls:
            client_cls.return_value.post.return_value = resp
            client, base, headers = ops._login(self._cfg())
            assert base == f"https://c2.example{ops._ENDPOINT_PATH}"
            assert headers == {"Authorization": "Bearer tok123"}
            _, kwargs = client_cls.call_args
            assert kwargs["verify"] is True  # M2: ssl verification default ON
            client_cls.return_value.post.assert_called_once()

    def test_encrypted_password_decrypted_before_send(self):
        resp = MagicMock()
        resp.json.return_value = {"access_token": "t"}
        with (
            patch.object(ops.httpx, "Client") as client_cls,
            patch.object(ops, "decrypt_str", return_value="decrypted"),
        ):
            client_cls.return_value.post.return_value = resp
            ops._login(self._cfg(password="__enc__ciphertext"))
            sent = client_cls.return_value.post.call_args[1]["json"]
            assert sent["password"] == "decrypted"

    def test_verify_ssl_false_honored(self):
        resp = MagicMock()
        resp.json.return_value = {"access_token": "t"}
        with patch.object(ops.httpx, "Client") as client_cls:
            client_cls.return_value.post.return_value = resp
            ops._login(self._cfg(verify_ssl=False))
            assert client_cls.call_args[1]["verify"] is False

    def test_ssrf_guard_applied(self):
        from fastapi import HTTPException

        with (
            patch.object(ops.httpx, "Client") as client_cls,
            patch(
                "app.core.ssrf_guard.validate_outbound_url",
                side_effect=HTTPException(400, "blocked"),
            ) as v,
        ):
            with pytest.raises(HTTPException):
                ops._login(self._cfg(url="http://169.254.169.254", allow_private_network=False))
            v.assert_called_once_with("http://169.254.169.254", allow_private=False)
            # the httpx client was never constructed — the gate fires first
            client_cls.assert_not_called()


def _stack_fixture(module_db, *, with_redirector=False, with_provider=False):
    """Stack + services (+ optional redirector link/provider), committed
    parent-first — plain-column FKs have no mapper ordering."""
    import uuid

    from app.core.utils import ts_now
    from app.models.infra_v2 import InfraStack, ServiceLink, StackService

    sfx = uuid.uuid4().hex[:8]
    st = InfraStack(id=f"stk_{sfx}", name="s", status="ready", created_at=ts_now())
    module_db.add(st)
    module_db.commit()
    c2 = StackService(
        id=f"svc_{sfx}_c2", stack_id=st.id, role="c2", name=f"c2-{sfx}", status="running"
    )
    module_db.add(c2)
    module_db.commit()
    redir_id = None
    if with_redirector:
        redir = StackService(
            id=f"svc_{sfx}_rd",
            stack_id=st.id,
            role="redirector",
            name=f"redir-{sfx}",
            status="running",
            connection_url="https://rd.example:8443",
            ports=[{"internal": 443, "external": 44333, "proto": "tcp"}],
        )
        module_db.add(redir)
        module_db.commit()
        redir_id = redir.id
        module_db.add(
            ServiceLink(
                id=f"lnk_{sfx}",
                stack_id=st.id,
                from_service_id=redir.id,
                to_service_id=c2.id,
                link_type="http_proxy",
                status="configured",
            )
        )
        module_db.commit()
    return st, c2, redir_id


class TestRedirectorHelpers:
    def test_no_redirector(self, module_db):
        st, c2, _ = _stack_fixture(module_db)
        assert ops._has_redirector(module_db, c2.id) is None
        assert ops._redirector_address(module_db, c2.id) is None

    def test_redirector_detected(self, module_db):
        st, c2, redir_id = _stack_fixture(module_db, with_redirector=True)
        assert (
            ops._has_redirector(module_db, c2.id)
            == module_db.query(
                __import__("app.models.infra_v2", fromlist=["StackService"]).StackService
            )
            .get(redir_id)
            .name
        )

    def test_redirector_address_from_connection_url(self, module_db):
        st, c2, redir_id = _stack_fixture(module_db, with_redirector=True)
        # no provider → address falls back to the service's connection_url
        addr = ops._redirector_address(module_db, c2.id)
        assert addr == "rd.example:44333"


class TestExposePortCePaths:
    """Not stack-bound / service gone / the edition gate — identical in
    both editions because ee_import is forced to None."""

    def test_not_stack_bound(self, module_db):
        r = ops.expose_port(module_db, {"id": "x"}, 8444, "ln")
        assert r == {
            "ok": True,
            "mode": "external",
            "message": "integration not stack-bound; assuming reachable",
        }

    def test_service_gone(self, module_db):
        with patch("app.core.editions.ee_import", return_value=None):
            r = ops.expose_port(
                module_db, {"service_id": "svc_missing", "stack_id": "stk_x"}, 8444, "ln"
            )
        assert r["mode"] == "external" and "gone" in r["message"]

    def test_edition_gate_assumes_reachable(self, module_db):
        st, c2, _ = _stack_fixture(module_db)
        with patch("app.core.editions.ee_import", return_value=None):
            r = ops.expose_port(module_db, {"service_id": c2.id, "stack_id": st.id}, 8444, "ln")
        assert r["ok"] is True
        assert "does not deploy" in r["message"]


class TestCreateListenerValidation:
    """Every field rejection must fire BEFORE the C2 or the cluster is
    touched (no leaked ports, no half-created state)."""

    def _integration(self, **kw):
        integ = {"id": "i", "url": "https://c2.example", "service_id": "", "stack_id": ""}
        integ.update(kw)
        return integ

    def test_invalid_name_rejected(self, module_db):
        from fastapi import HTTPException

        with patch.object(ops, "list_listeners", return_value=[]):
            with pytest.raises(HTTPException, match="letters/digits"):
                ops.create_listener(
                    module_db, self._integration(), {"name": "bad name!", "port": 8444}
                )

    def test_invalid_port_rejected(self, module_db):
        from fastapi import HTTPException

        with patch.object(ops, "list_listeners", return_value=[]):
            with pytest.raises(HTTPException, match="1-65535"):
                ops.create_listener(module_db, self._integration(), {"name": "ok", "port": 0})

    def test_invalid_domain_rejected(self, module_db):
        from fastapi import HTTPException

        with patch.object(ops, "list_listeners", return_value=[]):
            with pytest.raises(HTTPException, match="invalid characters"):
                ops.create_listener(
                    module_db,
                    self._integration(),
                    {"name": "ok", "port": 8444, "domain": "bad domain"},
                )

    def test_port_conflict_carries_suggestion(self, module_db):
        from fastapi import HTTPException

        live = [{"l_name": "existing", "l_bind_port": 8444}]
        with patch.object(ops, "list_listeners", return_value=live):
            with pytest.raises(HTTPException) as ei:
                ops.create_listener(module_db, self._integration(), {"name": "ok", "port": 8444})
            assert "suggested free port" in str(ei.value.detail)

    def test_duplicate_name_rejected(self, module_db):
        from fastapi import HTTPException

        with patch.object(
            ops, "list_listeners", return_value=[{"l_name": "dup", "l_bind_port": 9000}]
        ):
            with pytest.raises(HTTPException, match="already exists"):
                ops.create_listener(module_db, self._integration(), {"name": "dup", "port": 8445})


class TestCreateListenerLifecycle:
    def _integration(self, service_id="", stack_id=""):
        return {
            "id": "i",
            "url": "https://c2.example",
            "service_id": service_id,
            "stack_id": stack_id,
        }

    def test_happy_path(self, module_db):
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {"ok": True}
        client = MagicMock()
        client.post.return_value = ok_resp
        with (
            patch.object(ops, "list_listeners", return_value=[]),
            patch.object(ops, "expose_port", return_value={"ok": True, "mode": "external"}),
            patch.object(ops, "_login", return_value=(client, "https://c2.example", {})),
            patch.object(ops, "_has_redirector", return_value=None),
        ):
            r = ops.create_listener(module_db, self._integration(), {"name": "ln1", "port": 8444})
        assert r["ok"] is True
        assert r["listener"]["port"] == 8444
        # no redirector → TLS terminates on the listener itself
        assert r["tls"]["terminated_at"] == "listener" and r["tls"]["ssl"] is True
        client.close.assert_called_once()

    def test_c2_rejection_rolls_back_exposure(self, module_db):
        bad_resp = MagicMock()
        bad_resp.status_code = 200
        bad_resp.json.return_value = {"ok": False, "message": "nope"}
        bad_resp.text = "{}"
        client = MagicMock()
        client.post.return_value = bad_resp
        with (
            patch.object(ops, "list_listeners", return_value=[]),
            patch.object(ops, "expose_port", return_value={"ok": True, "mode": "k8s"}),
            patch.object(ops, "_login", return_value=(client, "https://c2.example", {})),
            patch.object(ops, "_has_redirector", return_value=None),
            patch.object(ops, "_unexpose_port") as unexpose,
        ):
            r = ops.create_listener(module_db, self._integration(), {"name": "ln2", "port": 8445})
        assert r["ok"] is False and "nope" in r["message"]
        unexpose.assert_called_once()  # nothing stays half-open

    def test_redirector_terminates_tls_and_sets_callback(self, module_db):
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {"ok": True}
        client = MagicMock()
        client.post.return_value = ok_resp
        with (
            patch.object(ops, "list_listeners", return_value=[]),
            patch.object(ops, "expose_port", return_value={"ok": True, "mode": "external"}),
            patch.object(ops, "_login", return_value=(client, "https://c2.example", {})),
            patch.object(ops, "_has_redirector", return_value="redir-1"),
            patch.object(ops, "_redirector_address", return_value="rd.example:44333"),
            patch.object(ops, "_switch_link_to_passthrough") as sw,
        ):
            # ssl unset → redirector present means TLS ends at the redirector
            r = ops.create_listener(module_db, self._integration(), {"name": "ln3", "port": 8446})
        assert r["tls"]["terminated_at"] == "redirector" and r["tls"]["ssl"] is False
        assert r["listener"]["callback"] == "rd.example:44333"
        sw.assert_not_called()  # passthrough only when the listener serves TLS


class TestStopListener:
    def _integration(self):
        return {"id": "i", "url": "https://c2.example", "service_id": "", "stack_id": ""}

    def test_stop_ok_first_try(self, module_db):
        ok = MagicMock()
        ok.status_code = 200
        ok.json.return_value = {"ok": True}
        ok.text = "{}"
        client = MagicMock()
        client.post.return_value = ok
        with (
            patch.object(ops, "_login", return_value=(client, "https://c2.example", {})),
            patch.object(ops, "_unexpose_port") as unexpose,
        ):
            r = ops.stop_listener(module_db, self._integration(), "ln1", "BeaconHTTP")
        assert r["ok"] is True
        unexpose.assert_called_once()

    def test_wrong_type_retry_uses_real_type(self, module_db):
        fail = MagicMock()
        fail.status_code = 200
        fail.json.return_value = {"ok": False}
        fail.text = "{}"
        ok = MagicMock()
        ok.status_code = 200
        ok.json.return_value = {"ok": True}
        ok.text = "{}"
        listed = MagicMock()
        listed.json.return_value = [{"l_name": "ln1", "l_reg_name": "BeaconTCP"}]
        client = MagicMock()
        client.post = MagicMock(side_effect=[fail, ok])
        client.get.return_value = listed
        with (
            patch.object(ops, "_login", return_value=(client, "https://c2.example", {})),
            patch.object(ops, "_unexpose_port"),
        ):
            r = ops.stop_listener(module_db, self._integration(), "ln1", "BeaconHTTP")
        assert r["ok"] is True
        retry_json = client.post.call_args_list[1][1]["json"]
        assert retry_json["type"] == "BeaconTCP"  # corrected from the live list


class TestUnexposePort:
    def test_reflected_ports_removed(self, module_db):
        st, c2, _ = _stack_fixture(module_db)
        c2.ports = [
            {"internal": 8443, "external": 8443},
            {"internal": 8444, "external": 30111, "_listener": "lnX"},
        ]
        module_db.commit()
        with patch.object(ops, "_expose_port_k8s_remove") as k8s_remove:
            ops._unexpose_port(module_db, {"service_id": c2.id}, "lnX")
            k8s_remove.assert_called_once()
        module_db.refresh(c2)
        assert all(p.get("_listener") != "lnX" for p in (c2.ports or []))

    def test_no_service_is_noop(self, module_db):
        with patch.object(ops, "_expose_port_k8s_remove") as k8s_remove:
            ops._unexpose_port(module_db, {"service_id": "svc_missing"}, "lnX")
            k8s_remove.assert_not_called()

    def test_no_service_id_early(self, module_db):
        assert ops._unexpose_port(module_db, {}, "lnX") is None  # no service: silent skip


class TestSwitchLinkPassthrough:
    def test_unbound_integration_returns_none(self, module_db):
        assert (
            ops._switch_link_to_passthrough(module_db, {"service_id": "", "stack_id": ""}, 8444)
            is None
        )

    def test_no_tunnel_link_returns_none(self, module_db):
        st, c2, _ = _stack_fixture(module_db)
        assert (
            ops._switch_link_to_passthrough(
                module_db, {"service_id": c2.id, "stack_id": st.id}, 8444
            )
            is None
        )

    def test_link_flipped_and_reconfigured(self, module_db):
        from app.models.infra_v2 import ServiceLink

        st, c2, _ = _stack_fixture(module_db)
        module_db.add(
            ServiceLink(
                id="lnk_pt",
                stack_id=st.id,
                from_service_id=c2.id,
                to_service_id=c2.id,
                link_type="reverse_tunnel",
                status="configured",
                config={"remote_port": 20022},
            )
        )
        module_db.commit()

        # inject a fake app.ee.infra.links into sys.modules — works in both
        # editions (CE has no real app.ee; EE's real one stays untouched)
        fake_links = types.ModuleType("app.ee.infra.links")
        mgr = MagicMock()
        mgr._configure_one = MagicMock(
            side_effect=lambda _stack, lnk, _svcs: setattr(lnk, "status", "configured")
        )
        fake_links.LinkManager = MagicMock(return_value=mgr)
        fake_pkg = types.ModuleType("app.ee")
        fake_infra = types.ModuleType("app.ee.infra")
        saved = {k: sys.modules.get(k) for k in ("app.ee", "app.ee.infra", "app.ee.infra.links")}
        sys.modules["app.ee"] = fake_pkg
        sys.modules["app.ee.infra"] = fake_infra
        sys.modules["app.ee.infra.links"] = fake_links
        try:
            r = ops._switch_link_to_passthrough(
                module_db, {"service_id": c2.id, "stack_id": st.id}, 8444
            )
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

        assert r is not None and r["ok"] is True
        lnk = module_db.query(ServiceLink).get("lnk_pt")
        assert lnk.config["tls_mode"] == "passthrough"
        assert lnk.config["backend_port"] == 8444  # aimed at the listener
        mgr._configure_one.assert_called_once()


class TestListenerContext:
    def test_used_and_suggested_ports(self, module_db):
        st, c2, _ = _stack_fixture(module_db)
        c2.ports = [{"internal": 8443, "external": 8443}, {"internal": 8444, "external": 30100}]
        module_db.commit()
        ctx = ops.listener_context(
            module_db,
            {"service_id": c2.id},
            [{"l_bind_port": 8445}, {"l_bind_port": "garbage"}],
        )
        assert 8443 in ctx["used_ports"] and 8444 in ctx["used_ports"] and 8445 in ctx["used_ports"]
        assert ctx["suggested_port"] == 8446
        assert ctx["service_ports"][0]["note"] == "teamserver / initial deployment"

    def test_no_service(self, module_db):
        ctx = ops.listener_context(module_db, {}, [])
        assert ctx["used_ports"] == [] and ctx["suggested_port"] == 8444


class TestOpsDispatchers:
    async def test_adaptix_runs_sync_in_thread(self, module_db):
        with patch.object(ops, "create_listener", return_value={"ok": True}) as cl:
            r = await ops.ops_create_listener(module_db, {"type": "adaptix"}, {"name": "x"})
            assert r == {"ok": True}
            cl.assert_called_once()

    async def test_stop_dispatch(self, module_db):
        with patch.object(ops, "stop_listener", return_value={"ok": True}) as sl:
            r = await ops.ops_stop_listener(module_db, {"type": "adaptix"}, "ln")
            assert r == {"ok": True}
            sl.assert_called_once()

    async def test_payload_dispatch(self):
        with patch.object(ops, "generate_payload", return_value={"ok": True}) as gp:
            r = await ops.ops_generate_payload({"type": "adaptix"}, {"listener": "ln"})
            assert r == {"ok": True}
            gp.assert_called_once()

    async def test_sliver_dispatch(self, module_db):
        import asyncio

        async def fake_list(integration):
            return [{"l_name": "s"}]

        with patch("app.core.c2ops.sliver.list_listeners", side_effect=fake_list):
            out = await ops.ops_list_listeners(module_db, {"type": "sliver"})
            assert out == [{"l_name": "s"}]
        assert asyncio  # imported for the to_thread paths elsewhere


class TestGeneratePayload:
    def test_roundtrip_and_listener_array(self):
        import base64

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "ok": True,
            "message": f"{base64.b64encode(b'impl.bin').decode()}:{base64.b64encode(b'MZx90').decode()}",
        }
        client = MagicMock()
        client.post.return_value = resp
        with patch.object(ops, "_login", return_value=(client, "https://c2.example", {})):
            r = ops.generate_payload({"url": "https://c2.example"}, {"listener": "ln1"})
        assert r["ok"] is True
        assert r["filename"] == "impl.bin"
        assert r["payload"] == b"MZx90"
        # listener_name MUST be a JSON array (bare string 404s server-side)
        assert client.post.call_args[1]["json"]["listener_name"] == ["ln1"]


# ── k8s live-patch paths (engine injected through ee_import) ─────────
import sys as _sys  # noqa: E402
import types as _types  # noqa: E402
from unittest.mock import patch as _patch  # noqa: E402

import app.core.c2ops.ops as _ops  # noqa: E402


def _fake_engine_and_deploy(monkeypatch):
    """Inject fake app.ee.infra.engine/deploy modules so the k8s branch
    runs identically in both editions (CE has no app.ee at all)."""
    target = MagicMock()
    target.kubeconfig = "apiVersion: v1"
    engine = MagicMock()
    engine._build_target.return_value = target
    deploy = MagicMock()
    deploy.resolve_mode.return_value = "k8s"

    for name, mod in (
        ("app.ee", _types.ModuleType("app.ee")),
        ("app.ee.infra", _types.ModuleType("app.ee.infra")),
        ("app.ee.infra.engine", _types.ModuleType("app.ee.infra.engine")),
        ("app.ee.infra.deploy", _types.ModuleType("app.ee.infra.deploy")),
    ):
        _sys.modules[name] = mod
    _sys.modules["app.ee.infra.engine"].__dict__["_build_target"] = engine._build_target
    _sys.modules["app.ee.infra.deploy"].__dict__["resolve_mode"] = deploy.resolve_mode

    def fake_ee_import(path):
        return {
            "infra.engine": _sys.modules["app.ee.infra.engine"],
            "infra.deploy": _sys.modules["app.ee.infra.deploy"],
        }.get(path)

    monkeypatch.setattr(_ops, "ee_import", None, raising=False)  # not used directly
    return fake_ee_import


class TestK8sExposePort:
    def _svc_with_provider(self, module_db, host=""):
        import uuid

        from app.core.utils import ts_now
        from app.models.infra_v2 import InfraProvider, InfraStack, StackService

        sfx = uuid.uuid4().hex[:8]
        st = InfraStack(id=f"stk_k8s_{sfx}", name="s", status="ready", created_at=ts_now())
        module_db.add(st)
        module_db.commit()
        svc = StackService(
            id=f"svc_k8s_{sfx}", stack_id=st.id, role="c2", name="C2 Lab", status="running"
        )
        module_db.add(svc)
        module_db.commit()
        prov = InfraProvider(
            id=f"pvp_k8s_{sfx}",
            org_id=None,
            name="k",
            type="kubernetes",
            host=host,
            created_at=ts_now(),
        )
        module_db.add(prov)
        module_db.commit()
        svc.provider_id = prov.id
        module_db.commit()
        return st, svc, prov

    def _inject(self, monkeypatch):
        target = MagicMock()
        target.kubeconfig = "apiVersion: v1"
        engine_mod = _types.ModuleType("app.ee.infra.engine")
        deploy_mod = _types.ModuleType("app.ee.infra.deploy")
        engine_mod._build_target = MagicMock(return_value=target)
        deploy_mod.resolve_mode = MagicMock(return_value="k8s")

        saved = {
            k: _sys.modules.get(k)
            for k in ("app.ee", "app.ee.infra", "app.ee.infra.engine", "app.ee.infra.deploy")
        }
        for name, mod in (
            ("app.ee", _types.ModuleType("app.ee")),
            ("app.ee.infra", _types.ModuleType("app.ee.infra")),
            ("app.ee.infra.engine", engine_mod),
            ("app.ee.infra.deploy", deploy_mod),
        ):
            _sys.modules[name] = mod

        def fake_ee_import(path):
            return {"infra.engine": engine_mod, "infra.deploy": deploy_mod}.get(path)

        monkeypatch.setattr("app.core.editions.ee_import", fake_ee_import)
        return saved

    def _restore(self, saved):
        for k, v in saved.items():
            if v is None:
                _sys.modules.pop(k, None)
            else:
                _sys.modules[k] = v

    def test_k8s_patch_with_nodeport_and_host(self, module_db, monkeypatch):
        st, svc, prov = self._svc_with_provider(module_db, host="203.0.113.60")
        saved = self._inject(monkeypatch)
        try:
            patch_out = {"rc": 0, "stdout": "", "stderr": ""}
            get_out = {
                "rc": 0,
                "stdout": '{"spec": {"ports": [{"name": "ln-ln1", "nodePort": 31234}]}}',
                "stderr": "",
            }
            with _patch(
                "app.core.k8s_client._run_kubectl", side_effect=[patch_out, get_out]
            ) as kubectl:
                r = _ops._expose_port_k8s(module_db, svc, 8444, "ln1")
            assert r == {
                "ok": True,
                "node_port": 31234,
                "node_host": "203.0.113.60",
                "mode": "k8s-live-patch",
            }
            assert kubectl.call_count == 2
            # reflected into the stack model for the UI/teardown
            module_db.refresh(svc)
            assert any(p.get("_listener") == "ln1" for p in (svc.ports or []))
        finally:
            self._restore(saved)

    def test_k8s_node_host_resolved_from_cluster(self, module_db, monkeypatch):
        st, svc, prov = self._svc_with_provider(module_db, host="")  # k8s: no host column
        saved = self._inject(monkeypatch)
        try:
            patch_out = {"rc": 0, "stdout": "", "stderr": ""}
            get_out = {
                "rc": 0,
                "stdout": '{"spec": {"ports": [{"name": "ln-ln1", "nodePort": 31235}]}}',
                "stderr": "",
            }
            nodes_out = {
                "rc": 0,
                "stdout": "Hostname=node1 InternalIP=10.1.2.3 ExternalIP=203.0.113.99 ",
                "stderr": "",
            }
            with _patch(
                "app.core.k8s_client._run_kubectl", side_effect=[patch_out, get_out, nodes_out]
            ):
                r = _ops._expose_port_k8s(module_db, svc, 8445, "ln1")
            # ExternalIP preferred over InternalIP
            assert r["node_host"] == "203.0.113.99" and r["node_port"] == 31235
        finally:
            self._restore(saved)

    def test_duplicate_patch_tolerated(self, module_db, monkeypatch):
        st, svc, prov = self._svc_with_provider(module_db, host="h1")
        saved = self._inject(monkeypatch)
        try:
            dup = {"rc": 1, "stdout": "", "stderr": "Error from server: Duplicate value"}
            get_out = {"rc": 1, "stdout": "", "stderr": "oops"}
            with _patch("app.core.k8s_client._run_kubectl", side_effect=[dup, get_out]):
                r = _ops._expose_port_k8s(module_db, svc, 8446, "ln1")
            assert r["ok"] is True and r["node_port"] is None
        finally:
            self._restore(saved)

    def test_hard_patch_error_reported(self, module_db, monkeypatch):
        st, svc, prov = self._svc_with_provider(module_db, host="h1")
        saved = self._inject(monkeypatch)
        try:
            bad = {"rc": 1, "stdout": "", "stderr": "forbidden: cannot patch"}
            with _patch("app.core.k8s_client._run_kubectl", side_effect=[bad]):
                r = _ops._expose_port_k8s(module_db, svc, 8447, "ln1")
            assert r["ok"] is False and "forbidden" in r["message"]
        finally:
            self._restore(saved)

    def test_expose_port_routes_k8s_by_mode(self, module_db, monkeypatch):
        st, svc, prov = self._svc_with_provider(module_db, host="h")
        saved = self._inject(monkeypatch)
        try:
            patch_out = {"rc": 0, "stdout": "", "stderr": ""}
            get_out = {"rc": 0, "stdout": '{"spec": {"ports": []}}', "stderr": ""}
            with (
                _patch("app.core.k8s_client._run_kubectl", side_effect=[patch_out, get_out]),
                _patch.object(
                    _ops, "_expose_port_k8s", return_value={"ok": True, "mode": "k8s-live-patch"}
                ) as k8s,
            ):
                integ = {"service_id": svc.id, "stack_id": st.id}
                r = _ops.expose_port(module_db, integ, 8448, "ln2")
            assert r["mode"] == "k8s-live-patch"
            k8s.assert_called_once()
        finally:
            self._restore(saved)

    def test_expose_port_docker_reports_manual(self, module_db, monkeypatch):
        # resolve_mode patched to "docker" at the seam — deterministic in
        # BOTH editions (CE has no deploy module to patch through)
        st, svc, prov = self._svc_with_provider(module_db, host="h")
        fake_deploy = _types.ModuleType("fake_deploy")
        fake_deploy.resolve_mode = MagicMock(return_value="docker")

        def fake_ee(path):
            return fake_deploy if path == "infra.deploy" else None

        monkeypatch.setattr("app.core.editions.ee_import", fake_ee)
        with _patch.object(_ops, "_expose_port_k8s") as k8s:
            integ = {"service_id": svc.id, "stack_id": st.id}
            r = _ops.expose_port(module_db, integ, 8449, "ln3")
        assert r["mode"] == "manual" and "recreate the container" in r["message"], r
        k8s.assert_not_called()

    def test_k8s_remove_patches_port_out(self, module_db, monkeypatch):
        st, svc, prov = self._svc_with_provider(module_db, host="h")
        saved = self._inject(monkeypatch)
        try:
            get_out = {
                "rc": 0,
                "stdout": '{"spec": {"ports": [{"name": "ln-lnX", "nodePort": 31234}, {"name": "other"}]}}',
                "stderr": "",
            }
            with _patch(
                "app.core.k8s_client._run_kubectl",
                side_effect=[get_out, {"rc": 0, "stdout": "", "stderr": ""}],
            ) as kubectl:
                _ops._expose_port_k8s_remove(module_db, svc, "lnX")
            patch_call = kubectl.call_args_list[1][0][0]
            assert patch_call[patch_call.index("patch")]  # a patch ran
            payload = patch_call[patch_call.index("-p") + 1]
            assert '"op": "remove"' in payload.replace("'", '"') or '"op":"remove"' in payload
        finally:
            self._restore(saved)
