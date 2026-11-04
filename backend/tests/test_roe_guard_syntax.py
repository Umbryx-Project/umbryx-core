"""roe_guard nmap-syntax expansion and literal checks (review 2026-10-29
HIGH finding) — unit level."""

import pytest

from app.core.roe_guard import _expand_nmap_token, _is_literal_ip


class TestIsLiteralIp:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("10.0.0.1", True),
            ("::1", True),
            ("host.example.com", False),
            ("10.0.0.1-50", False),  # range is NOT a single literal
            ("", False),
        ],
    )
    def test_literals(self, value, expected):
        assert _is_literal_ip(value) is expected


def _covers(nets, ip: str) -> bool:
    import ipaddress

    return any(ipaddress.ip_address(ip) in n for n in nets)


class TestExpandNmapToken:
    def test_integer_literal(self):
        assert [str(n) for n in _expand_nmap_token("167772161")] == ["10.0.0.1/32"]

    def test_hex_literal(self):
        assert [str(n) for n in _expand_nmap_token("0x0a000005")] == ["10.0.0.5/32"]

    def test_octet_range(self):
        nets = _expand_nmap_token("10.0.0.1-3")
        assert all(_covers(nets, f"10.0.0.{i}") for i in (1, 2, 3))
        assert not _covers(nets, "10.0.0.4")

    def test_wildcard(self):
        nets = _expand_nmap_token("10.0.5.*")
        assert _covers(nets, "10.0.5.0") and _covers(nets, "10.0.5.255")
        assert not _covers(nets, "10.0.4.1")

    def test_hostname_not_expanded(self):
        assert _expand_nmap_token("target.example.com") == []

    def test_garbage_rejected(self):
        assert _expand_nmap_token("999.999.999.999") == []

    def test_oversized_expansion_rejected(self):
        # a /17 wildcard is past the 65536 cap — rejected as a whole
        assert _expand_nmap_token("10.0-131.*") == []
