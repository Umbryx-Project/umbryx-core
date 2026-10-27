"""
Hardware identity for license binding (docs/modules/LICENSING_REDESIGN.md).

hwid is not a single hash but a *set* of per-parameter hashes in two classes:

- **anchors** — stable across reboots and minor hardware changes, and unchanged
  by cloning (`machine_id`, `cpu_sig`, `mem_gib`, `install_uuid`).
- **clone-sensitive** — regenerated / reassigned on a fresh clone
  (`product_uuid`, `primary_mac`, `cloud_instance_id`).

A license binds to this set and matches it *fuzzily*: enough anchors must still
match (tolerating a swapped disk/NIC/RAM), AND — when any were bound — at least
one clone-sensitive value must match. If every clone-sensitive value changed the
box is a clone/migration and the license requires re-activation, even though the
anchors match.

All collection is best-effort and never raises: a parameter that can't be read
is simply absent (and so doesn't count). Inside a stock container few real
signals exist; mount host anchors read-only for genuine binding — see the module
doc's container caveat.
"""
from __future__ import annotations

import hashlib
import re

ANCHORS = ("machine_id", "cpu_sig", "mem_gib", "install_uuid")
CLONE_SENSITIVE = ("product_uuid", "primary_mac", "cloud_instance_id")

# Defaults for the signed hwid policy. Kept conservative: tolerate hardware
# tweaks (need only 2 anchors) but still catch a clone (all clone-sensitive
# params changed).
DEFAULT_POLICY = {"min_anchor_matches": 2, "require_clone_sensitive": True}

# Read host anchors from these paths first (mount points), then the in-container
# fallbacks. See docker-compose backend volumes.
_MACHINE_ID_PATHS = ("/host/machine-id", "/etc/machine-id", "/var/lib/dbus/machine-id")
_PRODUCT_UUID_PATHS = ("/host/product_uuid", "/sys/class/dmi/id/product_uuid")


def _read_first(paths: tuple[str, ...]) -> str:
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="ignore") as fh:
                v = fh.read().strip()
            if v:
                return v
        except OSError:
            continue
    return ""


def _cpu_sig() -> str:
    try:
        model = ""
        count = 0
        with open("/proc/cpuinfo", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("model name") and not model:
                    model = line.split(":", 1)[1].strip()
                elif line.startswith("processor"):
                    count += 1
        if not model and count == 0:
            return ""
        return f"{model}|{count}"
    except OSError:
        return ""


def _mem_gib() -> str:
    try:
        with open("/proc/meminfo", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    kb = int(re.search(r"(\d+)", line).group(1))
                    # Round to whole GiB so a tiny reported-memory drift (or a
                    # hypervisor rounding difference) doesn't break the match.
                    return str(round(kb / (1024 * 1024)))
    except (OSError, AttributeError, ValueError):
        pass
    return ""


def _primary_mac() -> str:
    """First real NIC MAC: a non-loopback interface with a non-zero address,
    skipping obvious virtual bridges/veths where we can tell."""
    import os

    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return ""
    for name in names:
        if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr")):
            continue
        mac = _read_first((f"{base}/{name}/address",))
        if mac and mac != "00:00:00:00:00:00":
            return mac.lower()
    return ""


def collect_hwid(install_uuid: str) -> dict[str, str]:
    """Collect the raw hwid parameter values available on this host. Missing
    parameters are omitted. ``install_uuid`` is supplied by the caller (it is
    the instance's own persisted UUID, always present)."""
    raw = {
        "machine_id": _read_first(_MACHINE_ID_PATHS),
        "cpu_sig": _cpu_sig(),
        "mem_gib": _mem_gib(),
        "install_uuid": (install_uuid or "").strip(),
        "product_uuid": _read_first(_PRODUCT_UUID_PATHS),
        "primary_mac": _primary_mac(),
        # cloud_instance_id is fetched from the metadata service only in online
        # flows (needs network); omitted here to keep collection offline-safe.
    }
    return {k: v for k, v in raw.items() if v}


def hash_hwid(values: dict[str, str]) -> dict[str, str]:
    """Hash each raw value (namespaced by parameter) so the bound identity that
    leaves the box (in the .c2v request / the license) never carries raw
    machine values."""
    return {
        k: hashlib.sha256(f"{k}:{v}".encode()).hexdigest()
        for k, v in values.items()
        if v
    }


def current_hwid_hashes(install_uuid: str) -> dict[str, str]:
    return hash_hwid(collect_hwid(install_uuid))


def match_hwid(bound: dict[str, str], current: dict[str, str], policy: dict | None = None) -> dict:
    """Fuzzy-compare a license's bound hwid hashes against the current machine.

    Returns a report ``{ok, anchors_matched, clone_sensitive_bound,
    clone_sensitive_matched, reason}``. ``ok`` is True when enough anchors match
    AND (no clone-sensitive params were bound, or at least one still matches)."""
    policy = {**DEFAULT_POLICY, **(policy or {})}
    min_anchors = int(policy.get("min_anchor_matches", DEFAULT_POLICY["min_anchor_matches"]))
    require_cs = bool(policy.get("require_clone_sensitive", True))

    anchors_matched = sum(
        1 for p in ANCHORS if p in bound and bound[p] == current.get(p)
    )
    bound_cs = [p for p in CLONE_SENSITIVE if p in bound]
    cs_matched = sum(1 for p in bound_cs if bound[p] == current.get(p))

    ok_anchors = anchors_matched >= min_anchors
    # If clone-sensitive params were bound and required, at least one must still
    # match — otherwise the box is a clone/migration.
    ok_clone = (not require_cs) or (not bound_cs) or (cs_matched >= 1)

    if not ok_anchors:
        reason = f"too few hardware anchors match ({anchors_matched}/{min_anchors} required)"
    elif not ok_clone:
        reason = "all clone-sensitive parameters changed — looks like a clone/migration"
    else:
        reason = "ok"

    return {
        "ok": ok_anchors and ok_clone,
        "anchors_matched": anchors_matched,
        "clone_sensitive_bound": len(bound_cs),
        "clone_sensitive_matched": cs_matched,
        "reason": reason,
    }
