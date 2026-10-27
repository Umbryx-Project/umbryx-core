"""
Shared helpers for firewall/router config parsers — kept here so vendor
files don't reimplement the same small pieces of string plumbing.
"""

from __future__ import annotations

import ipaddress


def is_public_ip(ip: str) -> bool:
    """True if ip is a concrete, publicly-routable address.

    False for anything unparseable, RFC1918/CGNAT/loopback/link-local/
    multicast/reserved, or an object-group placeholder. Used to classify
    discovered interfaces as real external attack surface vs. internal
    inventory (core/firewall_enrich.py).
    """
    try:
        return ipaddress.ip_address(ip.strip()).is_global
    except (ValueError, AttributeError):
        return False


_HEX_DIGITS = set("0123456789abcdefABCDEF")

# (separator, hex-digits-per-group, number-of-groups) for every MAC style
# actually seen across these vendors' operational-command output:
# colon (Fortinet/PaloAlto/UniFi), Cisco dotted-quad (IOS/ASA "aabb.ccdd.eeff"),
# Huawei/MikroTik dashed either as 6x2 or 3x4 groups.
_MAC_SHAPES = (
    (":", 2, 6),
    ("-", 2, 6),
    (".", 4, 3),
    ("-", 4, 3),
)


def looks_like_mac(token: str) -> bool:
    """True for a MAC-shaped token in any separator style these vendors'
    ARP/DHCP-lease command output uses. Pure structural check (group count
    + hex digits) — no regex, so adversarial input can't cause pathological
    backtracking; also can't be confused with an IP (different separators/
    digit ranges) so it's safe to scan for opportunistically."""
    t = token.strip()
    for sep, group_len, n_groups in _MAC_SHAPES:
        parts = t.split(sep)
        if len(parts) == n_groups and all(
            len(p) == group_len and all(c in _HEX_DIGITS for c in p) for p in parts
        ):
            return True
    return False


def normalize_mac(token: str) -> str:
    """Canonicalize any recognized MAC shape to lowercase colon-separated
    form (aa:bb:cc:dd:ee:ff) — the form enrichment matches hosts on.
    Returns the input unchanged if it isn't MAC-shaped."""
    t = token.strip()
    for sep, group_len, n_groups in _MAC_SHAPES:
        parts = t.split(sep)
        if len(parts) == n_groups and all(
            len(p) == group_len and all(c in _HEX_DIGITS for c in p) for p in parts
        ):
            hexdigits = "".join(parts).lower()
            return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))
    return t


def looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token.strip())
        return True
    except ValueError:
        return False


def extract_ip_and_mac(tokens: list[str]) -> tuple[str, str] | None:
    """Pull the first IP-shaped and first MAC-shaped token out of an
    already-whitespace-split operational-table row, regardless of exact
    column layout/spacing. Returns None (→ "not a data row") when either
    is missing, which is what lets scan_operational_table() safely stop a
    block instead of misparsing an unrelated line."""
    ip = next((t for t in tokens if looks_like_ip(t)), None)
    mac = next((t for t in tokens if looks_like_mac(t)), None)
    if not ip or not mac:
        return None
    return ip, normalize_mac(mac)


def scan_operational_table(lines: list[str], header_match, row_parser) -> list:
    """Generic scanner for operational command output (ARP tables, DHCP
    lease lists) that operators paste into the same upload as the running
    config. `header_match(stripped_line) -> bool` recognizes the header
    row that opens a block; `row_parser(tokens) -> object | None` turns
    each following line's whitespace-split tokens into a result, or None
    to end the block (a blank line always ends it too). Safe against
    misfiring on ordinary config lines because row_parser is expected to
    require an IP-shaped *and* MAC-shaped token before accepting a row —
    see individual vendor callers.
    """
    results: list = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            in_block = False
            continue
        if header_match(stripped):
            in_block = True
            continue
        if not in_block:
            continue
        item = row_parser(stripped.split())
        if item is None:
            in_block = False
            continue
        results.append(item)
    return results


def split_kv_pairs(s: str) -> dict[str, str]:
    """Linear scan of `key=value key2="quoted value" flagword` —
    O(len(s)), no regex, so malformed/adversarial input can't trigger
    catastrophic backtracking. Shared by vendors whose config export uses
    this style (MikroTik, FortiOS `set` lines, UniFi-adjacent CLI dumps).
    """
    tokens: dict[str, str] = {}
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] == " ":
            i += 1
        if i >= n:
            break
        start = i
        while i < n and s[i] not in " =":
            i += 1
        key = s[start:i]
        if not key:
            i += 1
            continue
        if i < n and s[i] == "=":
            i += 1
            if i < n and s[i] == '"':
                i += 1
                vstart = i
                while i < n and s[i] != '"':
                    i += 1
                value = s[vstart:i]
                i += 1
            else:
                vstart = i
                while i < n and s[i] != " ":
                    i += 1
                value = s[vstart:i]
            tokens[key] = value
        else:
            tokens[key] = ""
    return tokens
