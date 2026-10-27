"""Infra outbound-call hardening: TLS policy + SSRF guard coverage.

Audit 2026-08-31, findings 3.4/3.5: infra health checks and link probes
shipped with verify=False and no SSRF guard on externally-derived URLs.
"""
from unittest.mock import MagicMock

import pytest

# Enterprise-only: every test here exercises the deployment layer's
# outbound guards, which a Community build cannot do. Skipped there
# rather than failed — see conftest.py::pytest_collection_modifyitems.
pytestmark = pytest.mark.ee




class TestInfraTlsVerify:
    def test_default_on(self, monkeypatch):
        monkeypatch.delenv("INFRA_TLS_VERIFY", raising=False)
        from app.ee.infra.tls import infra_tls_verify

        assert infra_tls_verify() is True

    @pytest.mark.parametrize("raw", ["false", "0", "no", "off", "FALSE"])
    def test_explicit_opt_out(self, monkeypatch, raw):
        monkeypatch.setenv("INFRA_TLS_VERIFY", raw)
        from app.ee.infra.tls import infra_tls_verify

        assert infra_tls_verify() is False

    def test_explicit_on(self, monkeypatch):
        monkeypatch.setenv("INFRA_TLS_VERIFY", "true")
        from app.ee.infra.tls import infra_tls_verify

        assert infra_tls_verify() is True


class TestGuardInfraUrl:
    def test_unix_socket_passes_through(self):
        from app.ee.infra.tls import guard_infra_url

        # Docker over a unix socket must not be rejected by the HTTP guard
        guard_infra_url("unix:///var/run/docker.sock")
        guard_infra_url("http+unix:///var/run/docker.sock")

    def test_private_allowed_when_admin_configured(self):
        from app.ee.infra.tls import guard_infra_url

        guard_infra_url("http://10.0.0.5:2375", allow_private=True)

    def test_private_rejected_without_allow(self):
        from fastapi import HTTPException

        from app.ee.infra.tls import guard_infra_url

        with pytest.raises(HTTPException):
            guard_infra_url("http://127.0.0.1:2375", allow_private=False)


class TestDiscoveryProbeHealthGuarded:
    def test_private_health_url_rejected(self):
        """health_url comes from external discovery data — a loopback target
        must not be probed (SSRF, audit 3.4)."""
        from app.ee.infra.discovery import ServiceDiscovery

        svc = MagicMock()
        svc.health_url = "http://169.254.169.254/latest/meta-data/"
        disc = object.__new__(ServiceDiscovery)
        assert disc.probe_health(svc) == "unreachable"

    def test_health_url_public_probed(self):
        from unittest.mock import patch

        from app.ee.infra.discovery import ServiceDiscovery

        svc = MagicMock()
        svc.health_url = "https://health.example.com/health"
        disc = object.__new__(ServiceDiscovery)
        with patch(
            "app.core.ssrf_guard.is_private_host", return_value=False
        ), patch("app.ee.infra.discovery.httpx.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            assert disc.probe_health(svc) == "healthy"
            # TLS verification must be ON by default now (audit 3.5)
            assert mock_get.call_args.kwargs.get("verify") is True


class TestLinkProbeGuarded:
    def _mk(self):
        from app.ee.infra.links import LinkManager

        lm = object.__new__(LinkManager)
        lnk = MagicMock()
        from_svc = MagicMock()
        from_svc.connection_url = "http://127.0.0.1:9000/"
        to_svc = MagicMock()
        return lm, lnk, from_svc, to_svc

    def test_http_proxy_loopback_rejected(self):
        lm, lnk, from_svc, to_svc = self._mk()
        ok, msg = lm._verify_http_proxy(lnk, from_svc, to_svc)
        assert ok is False
        assert "unsafe" in msg.lower() or "probe failed" in msg.lower()

    def test_proxy_chain_loopback_rejected(self):
        lm, lnk, from_svc, to_svc = self._mk()
        ok, msg = lm._verify_proxy_chain(lnk, from_svc, to_svc)
        assert ok is False


class TestProbeHealthSemantics:
    """probe_health: private lab targets are probed, link-local is never
    probed, and a masked-404 C2 counts as healthy (test55/HA finding,
    2026-09-15: Adaptix's HttpServer.error serves a custom 404 for every
    path outside its endpoint routes, so <400 was never achievable)."""

    def _probe(self, url, status_code=None):
        from unittest.mock import MagicMock, patch

        from app.ee.infra.discovery import ServiceDiscovery

        svc = MagicMock()
        svc.health_url = url
        disc = object.__new__(ServiceDiscovery)
        with patch("app.ee.infra.discovery.httpx.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=status_code)
            return disc.probe_health(svc), mock_get

    def test_private_rfc1919_probed_and_404_healthy(self):
        result, mock_get = self._probe("https://192.0.2.10:30369/", status_code=404)
        assert result == "healthy"
        assert mock_get.called, "RFC1918 lab targets must be probed, not SSRF-dropped"

    def test_5xx_is_unhealthy(self):
        result, _ = self._probe("https://10.1.2.3:8443/", status_code=503)
        assert result == "unhealthy"

    def test_link_local_never_probed(self):
        result, mock_get = self._probe("http://169.254.169.254/latest/meta-data/")
        assert result == "unreachable"
        assert not mock_get.called, "link-local must be blocked before any request"
