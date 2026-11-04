import ipaddress
import socket
from urllib.parse import urlparse

# Networks no outbound platform request may ever reach (unless an explicit
# allow_private flag is set for a stored, admin-verified endpoint).
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    # RFC 6598 CGNAT range - routing-table constant, not an endpoint
    ipaddress.ip_network("100.64.0.0/10"),  # NOSONAR
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),  # unspecified — on Linux connects to localhost (retest 2026-11-02)
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped (defense in depth; normalized below)
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
    ipaddress.ip_network("2002::/16"),  # 6to4
]

_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_6TO4 = ipaddress.ip_network("2002::/16")


def _normalized_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Unwrap translated IPv6 forms to their IPv4 equivalent.

    Blocks the classic bypass where ::ffff:127.0.0.1 / 64:ff9b::7f00:1 /
    2002:7f00:1:: evade an IPv4-only blocklist.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        v = int(ip)
        if ip in _IPV4_MAPPED or ip in _NAT64:
            return ipaddress.IPv4Address(v & 0xFFFFFFFF)
        if ip in _6TO4:
            return ipaddress.IPv4Address((v >> 32) & 0xFFFFFFFF)
    return ip


def _is_blocked_ip(ip) -> bool:
    ip = _normalized_ip(ip)
    for net in _BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            return True
    return False


def is_private_host(hostname: str) -> bool:
    hostname = (hostname or "").strip().strip("[]")
    if not hostname:
        return True
    # IP literal: check directly, no DNS (covers mapped/NAT64/6to4 literals).
    try:
        return _is_blocked_ip(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    # Resolve and check every returned address.
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _type, _proto, _canon, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if _is_blocked_ip(ip):
                return True
    except socket.gaierror:
        return True
    return False


def validate_outbound_url(url: str, timeout: float = 10.0, allow_private: bool = False) -> None:
    """Validate a URL is safe for outbound requests.

    Args:
        url: The URL to validate.
        timeout: DNS resolution timeout (not currently used).
        allow_private: If True, skip the private-network check.
            Use only for admin-configured trusted endpoints (e.g. local LLM proxies).

    Note: the private check happens at validation time; a DNS-rebinding TOCTOU
    remains theoretically possible for hostnames (a TTL-0 record can flip
    between validate and connect). Prefer IP-pinning at connect time for
    high-value sinks; literal translated-IPv6 bypasses are closed here.
    """
    from fastapi import HTTPException

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, f"Unsupported URL scheme: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(400, "Invalid URL: no hostname")
    if allow_private:
        return
    if is_private_host(hostname):
        raise HTTPException(
            400, f"Target hostname resolves to private/internal address: {hostname}"
        )
