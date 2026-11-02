"""
Session-aware transport advisor.

Given a target host in a project, recommends the best transport path:

  "c2"    — active C2 beacon on target (host has 'c2' tag);
             caller should use the C2 exec API instead of SSH
  "socks" — active pivot observation covers target CIDR and has a SOCKS
             listener; inject proxychains into the exec SSH config
  "direct"— no live session or pivot; plain SSH from attacker

Usage::

    advice = advise_transport(db, pid, target_ip="10.10.20.5")
    if advice.method == "socks":
        ssh_config = inject_into_ssh_config(ssh_config, advice)
    elif advice.method == "c2":
        # dispatch via C2 API
        ...
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

_LIVE_STATUSES = {"session", "access", "owned", "pwned"}


# ── Result type ───────────────────────────────────────────────────────


@dataclass
class TransportAdvice:
    method: str  # "c2" | "socks" | "direct"
    reason: str
    # populated when method == "socks"
    socks_type: str = "socks5"
    socks_host: str = ""
    socks_port: int = 1080
    pivot_host_id: str = ""
    pivot_obs_id: str = ""
    route_cidr: str = ""
    # populated when method == "c2"
    c2_host_id: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "reason": self.reason,
            "socks_type": self.socks_type,
            "socks_host": self.socks_host,
            "socks_port": self.socks_port,
            "pivot_host_id": self.pivot_host_id,
            "pivot_obs_id": self.pivot_obs_id,
            "route_cidr": self.route_cidr,
            "c2_host_id": self.c2_host_id,
        }


# ── Helpers ───────────────────────────────────────────────────────────


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _best_pivot(pivots, target_ip: str):
    """Return the tightest-prefix active pivot that covers target_ip, or None."""
    best = None
    best_pfx = -1
    for p in pivots:
        cidr = (p.route_cidr or "").strip()
        if not cidr or not _ip_in_cidr(target_ip, cidr):
            continue
        try:
            pfx = ipaddress.ip_network(cidr, strict=False).prefixlen
        except ValueError:
            pfx = 0
        if pfx > best_pfx:
            best_pfx = pfx
            best = p
    return best


def _socks_from_bind_address(bind: str) -> tuple[str, int]:
    """Parse 'host:port' or ':port' or 'port' from bind_address."""
    bind = (bind or "").strip()
    if not bind:
        return "", 1080
    if ":" in bind:
        parts = bind.rsplit(":", 1)
        host = parts[0] or "127.0.0.1"
        try:
            return host, int(parts[1])
        except ValueError:
            return host, 1080
    try:
        return "127.0.0.1", int(bind)
    except ValueError:
        return "", 1080


# ── Public API ────────────────────────────────────────────────────────


def advise_transport(
    db: Session,
    pid: str,
    target_ip: str,
) -> TransportAdvice:
    """Recommend the best transport to reach target_ip inside project pid.

    Priority:
        1. C2 beacon active on host (host has 'c2' tag)
        2. Active pivot observation whose route_cidr covers target_ip
        3. Direct SSH (default)
    """
    from .. import models

    if not target_ip:
        return TransportAdvice(method="direct", reason="no target IP")

    # 1. C2 session check -------------------------------------------------
    try:
        hosts = (
            db.query(models.Host)
            .filter(
                models.Host.pid == pid,
                (models.Host.ip == target_ip) | (models.Host.hostname == target_ip),
            )
            .all()
        )
        for h in hosts:
            if "c2" in (h.tags or []):
                return TransportAdvice(
                    method="c2",
                    reason=f"host {target_ip} has active C2 beacon",
                    c2_host_id=h.id,
                )
    except Exception as exc:
        logger.debug("transport: C2 check failed for %s: %s", target_ip, exc)

    # 2. Pivot SOCKS check ------------------------------------------------
    try:
        pivots = (
            db.query(models.PivotObservation)
            .filter(
                models.PivotObservation.pid == pid,
                models.PivotObservation.status == "active",
            )
            .all()
        )
        pivot = _best_pivot(pivots, target_ip)
        if pivot:
            # Prefer bind_address from the observation; fall back to pivot host IP
            socks_host, socks_port = _socks_from_bind_address(pivot.bind_address or "")
            if not socks_host and pivot.pivot_host_id:
                ph = db.query(models.Host).filter(models.Host.id == pivot.pivot_host_id).first()
                if ph and ph.ip:
                    socks_host = ph.ip
            if socks_host:
                return TransportAdvice(
                    method="socks",
                    reason=f"pivot covers {pivot.route_cidr} via {socks_host}:{socks_port}",
                    socks_type="socks5",
                    socks_host=socks_host,
                    socks_port=socks_port,
                    pivot_host_id=pivot.pivot_host_id or "",
                    pivot_obs_id=pivot.id,
                    route_cidr=pivot.route_cidr or "",
                )
    except Exception as exc:
        logger.debug("transport: pivot check failed for %s: %s", target_ip, exc)

    # 3. Direct SSH -------------------------------------------------------
    return TransportAdvice(method="direct", reason="no active C2 or pivot route")


def inject_into_ssh_config(ssh_config: dict, advice: TransportAdvice) -> dict:
    """Return ssh_config augmented with exec_proxy_* fields from advice.

    Only modifies the config when method == 'socks' and a socks_host is set.
    """
    if advice.method != "socks" or not advice.socks_host:
        return ssh_config
    return {
        **ssh_config,
        "exec_proxy_type": advice.socks_type,
        "exec_proxy_host": advice.socks_host,
        "exec_proxy_port": advice.socks_port,
    }
