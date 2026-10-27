import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_host(hostname: str) -> bool:
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _type, _proto, _canon, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            for net in _BLOCKED_NETWORKS:
                if ip in net:
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
