"""Bare-metal nginx deploy method (ssh_bare) — unit tests with mocked SSH."""

import pytest

# Enterprise-only: this module imports app.ee at import time, so in a
# Community tree (where the package is removed by scripts/build-ce.sh)
# there is nothing to test rather than something failing. Declared here
# instead of in a list in conftest, so a module that stops depending on
# the Enterprise package can drop the line with it.
pytest.importorskip("app.ee", reason="Enterprise Edition package not in this build")

from unittest.mock import patch

from app.ee.infra.deploy_method import DeployContext, DeployMethodRegistry, DeployTarget
from app.ee.infra.methods.bare_method import BareNginxMethod


def _ctx(**kw):
    base = dict(
        stack_id="stkdeadbeef",
        stack_name="test-stack",
        service_id="svc12345",
        service_name="redirector",
        role="redirector",
        image="nginx:latest",
        config={},
        ports=[{"internal": 80, "external": 8080, "protocol": "tcp"}],
        env={},
        volumes=[],
        config_files=[],
        domain="",
        container_id_existing="",
    )
    base.update(kw)
    return DeployContext(**base)


def _target():
    return DeployTarget(provider_type="ssh_host", host="10.0.0.1", port=22, ssh_user="root", ssh_key="")


class TestRegistry:
    def test_registered_for_ssh_hosts(self):
        assert DeployMethodRegistry.get("ssh_bare") is not None
        assert isinstance(DeployMethodRegistry.get("ssh_bare"), BareNginxMethod)
        assert "ssh_bare" in DeployMethodRegistry.get_for_provider("ssh_host")
        assert "ssh_bare" in DeployMethodRegistry.get_for_provider("hetzner")
        assert "ssh_bare" not in DeployMethodRegistry.get_for_provider("kubernetes")


class TestEnsureNginx:
    def test_present_skips_install(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.side_effect = [(0, "/usr/sbin/nginx\n", "")]
            assert m._ensure_nginx(_target()) == "present"
            assert ex.call_count == 1  # no manager probe, no install

    def test_missing_installs_with_detected_manager(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            # nginx missing; apt-get is the FIRST probed manager that exists
            ex.side_effect = [
                (1, "", ""),            # command -v nginx
                (0, "/usr/bin/apt-get\n", ""),  # command -v apt-get → found
                (0, "", "install ok"),   # apt install
            ]
            assert m._ensure_nginx(_target()) == "apt-get"
            install_cmd = ex.call_args_list[2].args[1]
            assert "apt-get install -y nginx" in install_cmd

    def test_no_manager_raises(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            # nginx missing; every manager probe fails
            ex.side_effect = [(1, "", "")] * 6
            try:
                m._ensure_nginx(_target())
                raise AssertionError("expected RuntimeError")
            except RuntimeError as e:
                assert "package manager" in str(e)


class TestDeploy:
    def test_full_flow_with_generated_conf(self):
        m = BareNginxMethod()
        ss = "State Recv-Q\nLISTEN 0 0.0.0.0:8080 0.0.0.0:*\n"
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.side_effect = [
                (0, "/usr/sbin/nginx\n", ""),        # ensure nginx
                (0, "", ""),                         # ensure running
                (0, "/etc/nginx/conf.d\n", ""),      # conf dir probe
                (0, "", ""),                         # write conf
                (0, "syntax is ok\n", ""),            # nginx -t
                (0, "", ""),                         # reload
                (0, ss, ""),                         # ss -tln
            ]
            r = m.deploy(_ctx(), _target())
        assert r.success, r.message
        assert r.method == "ssh_bare"
        assert r.container_id == "/etc/nginx/conf.d/umbryx-stkdeadb-redirector.conf"
        assert r.connection_url == "http://10.0.0.1:8080"
        write_cmd = ex.call_args_list[3].args[1]
        assert "listen 8080" in write_cmd  # generated server block from ports

    def test_config_files_win_over_generated(self):
        m = BareNginxMethod()
        conf = "server { listen 9999; return 200 'hi'; }"
        ctx = _ctx(config_files=[{"path": "/etc/nginx/conf.d/custom.conf", "content": conf}])
        ss = "LISTEN 0 0 0.0.0.0:9999 0.0.0.0:*\n"  # custom conf listens 9999, not ctx.ports
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.side_effect = [
                (0, "/usr/sbin/nginx\n", ""), (0, "", ""),
                (0, "/etc/nginx/conf.d\n", ""), (0, "", ""),
                (0, "ok", ""), (0, "", ""), (0, ss, ""),
            ]
            r = m.deploy(ctx, _target())
        assert r.success, r.message
        write_cmd = ex.call_args_list[3].args[1]
        assert conf in write_cmd
        assert r.connection_url.endswith(":9999")  # url follows the conf's listen

    def test_bad_config_rolls_back(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.side_effect = [
                (0, "/usr/sbin/nginx\n", ""), (0, "", ""),
                (0, "/etc/nginx/conf.d\n", ""), (0, "", ""),
                (1, "", "emerg: unexpected end"),  # nginx -t fails
                (0, "", ""),                       # rollback rm
            ]
            r = m.deploy(_ctx(), _target())
        assert not r.success
        assert "nginx -t" in r.message
        assert "rm -f" in ex.call_args_list[5].args[1]

    def test_port_not_listening_fails(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.side_effect = [
                (0, "/usr/sbin/nginx\n", ""), (0, "", ""),
                (0, "/etc/nginx/conf.d\n", ""), (0, "", ""),
                (0, "ok", ""), (0, "", ""), (0, "LISTEN 0 0.0.0.0:22\n", ""),
            ]
            r = m.deploy(_ctx(), _target())
        assert not r.success
        assert "not listening" in r.message
        assert "8080" in r.message


class TestDestroyStatus:
    def test_destroy_removes_only_conf(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.return_value = (0, "", "")
            r = m.destroy(_ctx(container_id_existing="/etc/nginx/conf.d/umbryx-x.conf"), _target())
        assert r.success
        cmd = ex.call_args_list[0].args[1]
        assert "rm -f /etc/nginx/conf.d/umbryx-x.conf" in cmd
        assert "nginx -t" in cmd  # reload only when the rest still parses
        assert "apt" not in cmd and "apk" not in cmd  # never uninstall nginx

    def test_destroy_without_nginx_installed(self):
        """nginx absent (failed early deploy) — teardown still succeeds."""
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.return_value = (0, "", "")
            r = m.destroy(_ctx(container_id_existing="/etc/nginx/conf.d/umbryx-y.conf"), _target())
        assert r.success
        cmd = ex.call_args_list[0].args[1]
        assert "command -v nginx" in cmd  # guarded reload

    def test_status(self):
        m = BareNginxMethod()
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.return_value = (0, "active\n", "")
            assert m.status(_ctx(), _target()) == "running"
            ex.return_value = (1, "", "")
            ex2 = [(1, "", ""), (0, "", "")]  # not active, conf still there
            ex.side_effect = ex2
            assert m.status(_ctx(), _target()) == "stopped"


class TestConfDirDetection:
    def test_alpine_httpd_dir_preferred(self):
        """Alpine: http-context includes live in http.d/, not conf.d/ —
        a server{} block in conf.d/ would land in root context."""
        m = BareNginxMethod()
        ss = "LISTEN 0 0 0.0.0.0:8080 0.0.0.0:*\n"
        with patch.object(BareNginxMethod, "_ssh_exec_raw") as ex:
            ex.side_effect = [
                (0, "/usr/sbin/nginx\n", ""),        # nginx present
                (0, "", ""),                          # running
                (0, "/etc/nginx/http.d\n", ""),       # dir probe → alpine
                (0, "", ""),                          # write conf
                (0, "ok", ""),                        # nginx -t
                (0, "", ""),                          # reload
                (0, ss, ""),
            ]
            r = m.deploy(_ctx(), _target())
        assert r.success, r.message
        assert r.container_id == "/etc/nginx/http.d/umbryx-stkdeadb-redirector.conf"
        write_cmd = ex.call_args_list[3].args[1]
        assert "/etc/nginx/http.d/umbryx-stkdeadb-redirector.conf" in write_cmd
