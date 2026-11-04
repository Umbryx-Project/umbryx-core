"""
Engagement-boundary enforcement for job creation.

Prior to this module, a project's CIDR scope and Rules of Engagement (ROE)
were stored and displayed in the UI but never checked before a job actually
ran a command against a target — see docs/modules/COMPREHENSIVE_AUDIT_2026-08-31.md
findings 4.1.1/4.1.2. This module is the enforcement gate, called from the two
functions that create every job in the system (`job_tracker.start_job` and
`job_tracker.queue_job`).

Deliberately narrow scope for this first pass:
- ROE `forbidden_activities` / `requires_approval` ARE enforced now
  (implementer's decision during the 2026-08-31 fix wave, confirmed by
  the product owner post-hoc on 2026-09-01): a static connector→category mapping
  (see `_ACTIVITY_MAP`) plus per-project raw keys (`connector:nmap`,
  `connector:attacker_ssh:exec`) listable directly in the ROE — the
  "mapping in ROE config" override. Forbidden → the job fails with the
  reason; requires-approval → the job is held in `awaiting_approval`
  until a project admin approves it via the jobs API.
- CIDR ranges beyond a literal IP still need the range-behavior decision
  (resolved 2026-08-31: reject the whole job — implemented in
  check_target_scope_range).
- Only ROE work-hours and CIDR scope are enforced time/space-wise.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from .. import models
from .scan_helpers import load_scope_exclusions, load_scope_networks

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - py<3.9 not supported by this project
    ZoneInfo = None  # type: ignore[assignment,misc]


class EngagementViolation(Exception):
    """Raised when a job target/time falls outside the project's ROE/scope."""


class ApprovalRequired(Exception):
    """Raised when the ROE lists the job's activity under requires_approval.

    The job is created in a non-executing 'awaiting_approval' state; a
    project admin approves or rejects it via the jobs API, and only an
    approval queues it for execution."""

    def __init__(self, activities: list[str]):
        self.activities = sorted(activities)
        super().__init__(
            "ROE requires approval for: "
            + ", ".join(self.activities)
            + ". The job is held in 'awaiting_approval' until a project admin approves it."
        )


# Static default mapping from a job's connector/operation to ROE activity
# categories — implementer's call from the 2026-08-31 fix wave,
# confirmed by the product owner post-hoc on 2026-09-01. Projects can override or
# extend per-activity AND per-connector in the ROE itself by listing raw
# keys like "connector:nmap" or "connector:attacker_ssh:exec" in
# forbidden_activities / requires_approval — those match regardless of this
# table (the "mapping in ROE config" half of the decision).
_ACTIVITY_MAP: dict[tuple[str, str], set[str]] = {
    ("nmap", "scan"): {"port_scanning"},
    ("nuclei", "scan"): {"web_scanning"},
    ("httpx", "scan"): {"web_scanning"},
    ("ffuf", "scan"): {"web_scanning"},
    ("netexec", "scan"): {"ad_recon", "credential_stuffing"},
    ("donpapi", "scan"): {"credential_stuffing", "lateral_movement"},
    ("attacker_ssh", "exec"): {"lateral_movement"},
    ("c2", "exec"): {"lateral_movement"},
}

# Known ROE activity categories (frontend RoeView list) — used only to
# explain rejections; unknown categories in ROE lists still match the
# static map by name.
ROE_ACTIVITY_CATEGORIES = {
    "web_scanning",
    "port_scanning",
    "ad_recon",
    "exploitation",
    "phishing",
    "social_engineering",
    "wireless_attack",
    "physical_access",
    "dos_testing",
    "credential_stuffing",
    "lateral_movement",
    "privilege_escalation",
}


def job_activity_tags(connector_key: str, operation: str) -> set[str]:
    """Everything a ROE list can match on for this job: the mapped activity
    categories plus the raw connector keys (`connector:nmap`,
    `connector:nmap:scan`)."""
    tags = set(_ACTIVITY_MAP.get((connector_key or "", operation or ""), set()))
    if connector_key:
        tags.add(f"connector:{connector_key}")
        if operation:
            tags.add(f"connector:{connector_key}:{operation}")
    return tags


def _is_literal_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _target_networks(target: str) -> list:
    """Parse a job target into explicit networks where possible.

    Handles single IPs, CIDR notation, `a-b` ranges and comma/space
    separated lists of the above. Returns [] for hostnames/URLs/anything
    unparseable (those keep the historical no-check behaviour)."""
    if not target:
        return []
    nets: list = []

    def _parse_one(token: str) -> None:
        token = token.strip().strip("/").rstrip("/")
        if not token:
            return
        # strip scheme/host parts of URLs: http://10.0.0.5:8080/path
        if "://" in token:
            token = token.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        elif ":" in token and not _is_literal_ip(token):
            # host:port — keep host part only if it parses as an IP
            host = token.split(":", 1)[0]
            if _is_literal_ip(host):
                token = host
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
            return
        except ValueError:
            pass
        expanded = _expand_nmap_token(token)
        if expanded:
            nets.extend(expanded)
            return
        if "-" in token:
            lo, _, hi = token.partition("-")
            try:
                lo_ip = ipaddress.ip_address(lo.strip())
                hi_ip = ipaddress.ip_address(hi.strip())
                if lo_ip <= hi_ip:
                    nets.extend(ipaddress.summarize_address_range(lo_ip, hi_ip))
                    return
            except ValueError:
                pass

    for chunk in target.replace(",", " ").split():
        _parse_one(chunk)
    return nets


def _expand_nmap_token(token: str) -> list:
    """Expand nmap-style target syntax into explicit networks.

    External review 2026-10-29 (HIGH): nmap octet ranges (`10.0.0.1-50`),
    wildcards (`10.0.*.*`) and integer/hex literals (`167772161`,
    `0x0a000005`) sailed past `_target_networks` — jobs against them were
    never scope-checked. Returns [] for anything that is not clearly
    this syntax (hostnames keep the documented no-check behaviour).
    Capped: tokens expanding past 65536 addresses are rejected as a
    whole (an operator pasting that is not aiming at a /16 by accident).
    """
    import re as _re

    token = token.strip()
    if not token:
        return []
    # integer / hex IPv4 literal — ONLY when large enough to actually be
    # one (>= 1.0.0.0, i.e. >= 2**24). Small bare integers are port
    # numbers, timeouts and flag values in whole-command scanning (retest
    # 2026-11-02: '-p 80' became phantom target 0.0.0.80 and broke the
    # built-in stealth profile in any CIDR-scoped project).
    if _re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", token):
        try:
            value = int(token, 0)
        except ValueError:
            return []
        if not (2**24 <= value <= 0xFFFFFFFF):
            return []
        return [ipaddress.ip_network(str(ipaddress.ip_address(value)))]
    # dotted quad with per-octet n | n-m | *
    if not _re.fullmatch(r"[\d*\-]+\.[\d*\-]+\.[\d*\-]+\.[\d*\-]+", token):
        return []
    octets = []
    for part in token.split("."):
        if part == "*":
            octets.append(range(0, 256))
        elif "-" in part:
            lo, _, hi = part.partition("-")
            if not (lo.isdigit() and hi.isdigit()):
                return []
            lo_i, hi_i = int(lo), int(hi)
            if lo_i > hi_i or hi_i > 255:
                return []
            octets.append(range(lo_i, hi_i + 1))
        elif part.isdigit() and int(part) <= 255:
            octets.append(range(int(part), int(part) + 1))
        else:
            return []
    total = 1
    for o in octets:
        total *= len(o)
    if total > 65536:
        raise EngagementViolation(
            f"Target '{token}' expands past 65536 addresses — split it "
            "into explicit CIDRs so the scope check can reason about it."
        )
    addrs = [
        ipaddress.ip_address((a << 24) | (b << 16) | (c << 8) | d)
        for a in octets[0]
        for b in octets[1]
        for c in octets[2]
        for d in octets[3]
    ]
    return list(ipaddress.collapse_addresses(ipaddress.ip_network(f"{a}/32") for a in addrs))


def check_target_scope(db, pid: str, target: str) -> None:
    """Reject targets outside the project's defined in-scope CIDR ranges.

    Single IPs and RANGE targets alike (CIDR `10.0.0.0/24`, `a-b`,
    comma-separated lists, URL host parts) must be FULLY contained in the
    scope — implementer's decision from the 2026-08-31 fix wave,
    confirmed by the product owner post-hoc on 2026-09-01 (audit 4.1.2):
    a range that even
    partially sticks out rejects the whole job with the offending addresses
    listed, rather than silently narrowing or partially scanning. No-op for
    non-IP targets or when no CIDR scope is defined."""
    if not target:
        return
    nets = _target_networks(target)
    if not nets:
        return
    exclusions = load_scope_exclusions(db, pid)
    for net in nets:
        if any(net.version == x.version and net.overlaps(x) for x in exclusions):
            raise EngagementViolation(
                f"Target range {net} intersects an EXCLUDED range "
                f"({', '.join(str(x) for x in exclusions if net.overlaps(x))}) — "
                "client-protected asset. The whole job is rejected."
            )
    networks = load_scope_networks(db, pid)
    if not networks:
        return
    outside = []
    for net in nets:
        if not any(
            net.subnet_of(scope_net) if net.version == scope_net.version else False
            for scope_net in networks
        ):
            outside.append(str(net))
    if outside:
        preview = ", ".join(outside[:5]) + (" …" if len(outside) > 5 else "")
        exc = EngagementViolation(
            f"Target range(s) outside the project's defined scope: {preview}. "
            "The whole job is rejected — request a scope change or split the "
            "target into fully in-scope ranges."
        )
        # Surfaced to the UI alert so the operator can act on exactly these
        # ranges (request a scope extension) instead of re-parsing prose.
        exc.out_of_scope = outside[:20]
        raise exc


def check_roe_work_hours(db, pid: str) -> None:
    """Reject job creation outside the ROE's configured work-hours window,
    evaluated in the ROE's own timezone. No-op if the project has no ROE or
    the ROE doesn't define both a start and end time."""
    roe = db.query(models.ProjectROE).filter(models.ProjectROE.project_id == pid).first()
    if not roe or not roe.work_hours_start or not roe.work_hours_end:
        return
    tz = None
    if ZoneInfo and roe.timezone:
        try:
            tz = ZoneInfo(roe.timezone)
        except Exception:
            tz = None
    now = datetime.now(tz) if tz else datetime.utcnow()
    now_hm = now.strftime("%H:%M")
    start, end = roe.work_hours_start, roe.work_hours_end
    in_window = (start <= now_hm <= end) if start <= end else (now_hm >= start or now_hm <= end)
    if not in_window:
        raise EngagementViolation(
            f"Current time {now_hm} ({roe.timezone}) is outside the ROE-approved "
            f"work-hours window {start}-{end}."
        )


def check_roe_activities(
    db, pid: str, connector_key: str, operation: str, *, check_requires: bool = True
) -> None:
    """Enforce forbidden_activities / requires_approval (audit 4.1.1).

    Raises EngagementViolation for a forbidden activity, ApprovalRequired
    for one that needs sign-off (unless ``check_requires=False`` — used by
    the approval endpoint itself, which re-verifies everything *except* the
    requirement it is resolving). No-op if the project has no ROE or the ROE
    lists nothing relevant — enforcement only ever restricts what the ROE
    explicitly restricted."""
    roe = db.query(models.ProjectROE).filter(models.ProjectROE.project_id == pid).first()
    if not roe:
        return
    tags = job_activity_tags(connector_key, operation)
    if not tags:
        return
    forbidden = set(roe.forbidden_activities or [])
    hit_forbidden = tags & forbidden
    if hit_forbidden:
        raise EngagementViolation(
            "Activity forbidden by ROE: "
            + ", ".join(sorted(hit_forbidden))
            + f" (job {connector_key}/{operation})."
        )
    if not check_requires:
        return
    requires = set(roe.requires_approval or [])
    hit_requires = tags & requires
    if hit_requires:
        raise ApprovalRequired(sorted(hit_requires))


def check_engagement_rules(
    db,
    pid: str,
    target: str = "",
    connector_key: str = "",
    operation: str = "",
    command: str = "",
    target_is_pivot: bool = False,
) -> None:
    """Combined ROE/scope gate. Raises EngagementViolation on the first
    violation found; raises ApprovalRequired when the activity needs ROE
    sign-off. Call before a job actually sends any traffic/command.

    `target` alone isn't enough for exec-style jobs (attacker-exec, and any
    future connector shaped like it): there `target` is the SSH pivot host,
    not the real operation target, which only exists as a free-form
    argument inside `command` (e.g. `nmap -sT 203.0.113.5` run through an
    in-scope pivot) — a pivot inside scope let an operator hit any target
    the command names, completely bypassing the CIDR guard (security
    retest, 2026-09-03). `command` is best-effort scanned for the same
    IP/CIDR/range literals `check_target_scope` already looks for; it can't
    catch a target an operator deliberately obfuscates in shell (base64,
    variables, DNS names), but it closes the plain-text case, which is what
    every real usage looks like."""
    check_roe_work_hours(db, pid)
    check_roe_activities(db, pid, connector_key, operation)
    # target_is_pivot: exec-style jobs (attacker-exec and friends) carry
    # the SSH PIVOT — our own attacker box — in `target`, not a scan
    # target. The attacker machine is infrastructure and usually sits
    # OUTSIDE the engagement CIDR scope; treating it as a target broke
    # every command the moment a project defined its scope (found live on
    # the cyber-range stand). The command's literals still get scanned —
    # the out-of-scope-target-via-in-scope-pivot bypass this guard exists
    # for (2026-09-03) is unaffected.
    if not target_is_pivot:
        check_target_scope(db, pid, target)
    if command:
        check_target_scope(db, pid, command)
