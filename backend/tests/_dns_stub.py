"""Deterministic public DNS stub for SSRF-guard-dependent tests.

Runners in filtered networks (isolated docker test networks, some CI
hosts) resolve api.telegram.org / api.openai.com / hooks.slack.com to
PRIVATE addresses — upstream DNS falsification. The SSRF guard then
correctly rejects the URL and every "success-path" dispatch test fails
on ENVIRONMENT, not on code (seen on the postgres CI job 2026-10-20:
"Target hostname resolves to private/internal address").

Patch the guard's resolver to a fixed public address for the duration
of a test instead — the validation still runs, against an address with
the semantics the tests were written for.
"""

import socket
from contextlib import contextmanager
from unittest.mock import patch

PUBLIC_ADDR = "93.184.216.34"  # example.com — reserved documentation-ish public IP


def _public_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDR, 0))]


@contextmanager
def public_dns():
    """Make ssrf_guard.validate_outbound_url see every host as public."""
    with patch("app.core.ssrf_guard.socket.getaddrinfo", side_effect=_public_getaddrinfo):
        yield
