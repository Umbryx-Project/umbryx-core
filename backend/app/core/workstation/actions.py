"""Workstation action logging — shell hook injection and ingest.

A bash DEBUG-trap in the workstation shell POSTs every command to the
platform with a per-workstation bearer token. The hook is idempotent
(marker-delimited block in /etc/bash.bashrc) and travels over the same
management channel provisioning already uses (docker exec / kubectl exec),
so no new surface is opened on the workstation.

Attribution: the hook reports the shell $USER. Container workstations
log in as root, so per-command attribution is by workstation — and per
operator via the workstation pool (each member accesses pool machines
with their own key) or the single owner of a project workstation.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import subprocess

from sqlalchemy.orm import Session

from ...models.workstation_action import WorkstationAction
from ..utils import new_id, ts_now

logger = logging.getLogger(__name__)

HOOK_BEGIN = "# UMBRYX-AUDIT-BEGIN"
HOOK_END = "# UMBRYX-AUDIT-END"

HOOK_TEMPLATE = f"""{HOOK_BEGIN}
export UMBRYX_LOG_URL="__UMBRYX_URL__"
export UMBRYX_LOG_TOKEN="__UMBRYX_TOKEN__"
__umbryx_mark() {{
  # termtrack: OSC-7770 marker with the base64 command line, written to
  # the terminal right before execution. Terminals drop unknown OSC
  # sequences (invisible to the operator); the script(1) recording keeps
  # it — per-command segmentation of the PTY stream for free.
  local b; b=$(printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 2>/dev/null)
  [ -n "$b" ] && printf '\033]7770;umbryx;cmd;%s\007' "$b"
}}
__umbryx_log() {{
  # zsh preexec passes the CURRENT command line as $1 — exact even with
  # SHARE_HISTORY interleaving from other sessions (history 1 would return
  # whoever typed last). Fallback (bash DEBUG trap): history.
  local c; c="${{1:-$(history 1 2>/dev/null | sed 's/^ *[0-9]* *//')}}"
  [ -z "$c" ] && return
  __umbryx_mark "$c"
  local j; j=$(printf '%s' "$c" | sed 's/\\/\\\\/g; s/"/\\"/g' | head -c 2000)
  local u="${{USER:-$(id -un)}}"
  local sc="${{SSH_CLIENT:-}}"
  (curl -s -m 2 -X POST "$UMBRYX_LOG_URL" \
     -H "Authorization: Bearer $UMBRYX_LOG_TOKEN" \
     -H 'Content-Type: application/json' \
     -d "{{\"command\":\"$j\",\"user\":\"$u\",\"cwd\":\"${{PWD//\"/}}\",\"ssh_client\":\"$sc\",\"tty\":\"${{TTY:-}}\"}}" >/dev/null 2>&1 &)
}}
if [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null
  add-zsh-hook preexec __umbryx_log 2>/dev/null || preexec() {{ __umbryx_log; }}
else
  trap '__umbryx_log' DEBUG
fi
{HOOK_END}"""


HOOK_PULL_TEMPLATE = f"""{HOOK_BEGIN}
__umbryx_mark() {{
  # termtrack: OSC-7770 marker into the terminal right before execution
  # (pull machines included — the PTY harvester needs them to segment)
  local b; b=$(printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 2>/dev/null)
  [ -n "$b" ] && printf '\033]7770;umbryx;cmd;%s\007' "$b"
}}
__umbryx_log() {{
  # zsh preexec passes the CURRENT command line as $1 — exact even with
  # SHARE_HISTORY interleaving from other sessions (history 1 would return
  # whoever typed last). Fallback (bash DEBUG trap): history.
  local c; c="${{1:-$(history 1 2>/dev/null | sed 's/^ *[0-9]* *//')}}"
  [ -z "$c" ] && return
  __umbryx_mark "$c"
  local j; j=$(printf '%s' "$c" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g' | head -c 2000)
  local u="${{USER:-$(id -un)}}"
  local sc="${{SSH_CLIENT:-}}"
  mkdir -p "$HOME/.umbryx" 2>/dev/null
  printf '{{"ts":"%s","command":"%s","user":"%s","cwd":"%s","ssh_client":"%s","tty":"%s"}}\\n' \\
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$j" "$u" "${{PWD//\\"/}}" "$sc" "${{TTY:-}}" \\
    >> "$HOME/.umbryx/audit.log" 2>/dev/null
}}
if [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null
  add-zsh-hook preexec __umbryx_log 2>/dev/null || preexec() {{ __umbryx_log; }}
else
  trap '__umbryx_log' DEBUG
fi
{HOOK_END}"""


def ensure_token(db: Session, ws) -> str:
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    token = meta.get("action_log_token")
    if not token:
        token = secrets.token_hex(20)
        meta["action_log_token"] = token
        ws.meta = meta
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(ws, "meta")
        db.commit()
    return token


def _platform_log_url(db: Session) -> str:
    """Base URL workstations use to reach the platform API."""
    return _callback_url_candidates(db)[0]


def _callback_url_candidates(db: Session) -> list[str]:
    """Callback base URLs to try, in priority order.

    PUBLIC_BASE_URL wins if configured; otherwise every local address
    (VIP remnants last). The enable flow probes them FROM the machine and
    picks the first that actually answers — a hook installed with an
    unreachable URL silently swallows every action (found live: a lab VM
    on a routed segment could reach none of the platform's addresses)."""
    bases: list[str] = []
    env_base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    if env_base:
        bases.append(env_base)
    env_host = os.environ.get("PLATFORM_HOST", "")
    if env_host:
        bases.append(f"http://{env_host}:8888")
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        hosts = [h for h in r.stdout.split()]
        normal = [h for h in hosts if not h.endswith(".200")]
        vip_last = normal + [h for h in hosts if h.endswith(".200")]
        bases.extend(f"http://{h}:8888" for h in vip_last)
    except Exception:
        pass
    if not bases:
        bases.append("http://127.0.0.1:8888")
    out, seen = [], set()
    for b in bases:
        if b not in seen:
            seen.add(b)
            out.append(f"{b}/api/workstations/ws-actions")
    return out


def pick_callback_url(db: Session, ws) -> tuple[str, str | None]:
    """Probe the candidate URLs from the machine itself; returns
    (url, None) on success or (first_candidate, reason) when the machine
    can't reach any of them."""
    from ...models import OperatorWorkstation  # noqa: F401 — typing only

    argv, reason = _exec_channel(db, ws)
    if reason:
        return _callback_url_candidates(db)[0], reason
    candidates = _callback_url_candidates(db)
    probe = "; ".join(
        f"curl -s -m 3 -o /dev/null -w '%{{http_code}} {u}' {u.rsplit('/api/', 1)[0]}/api/health"
        for u in candidates
    )
    script = f"{probe} 2>/dev/null; true"
    if argv == ["__ssh__"]:
        from ..ssh_exec import run_ssh_command
        from .pool import _ssh_config_for

        cfg = _ssh_config_for(ws, db)
        if not cfg:
            return candidates[0], "machine has no access address"
        r = run_ssh_command(cfg, script, 20)
        out = (r.get("stdout") or "") if r.get("ok") else (r.get("stderr") or r.get("error") or "")
    else:
        import subprocess as sp

        rp = sp.run(argv + ["sh", "-c", script], capture_output=True, text=True, timeout=25)
        out = (rp.stdout or "") + (rp.stderr or "")
    for u in candidates:
        if f"200 {u}" in out:
            return u, None
    return candidates[0], (
        f"machine cannot reach the platform on any known address "
        f"({', '.join(u.rsplit('/api/', 1)[0] for u in candidates)}); set PUBLIC_BASE_URL "
        f"to an address reachable from the workstation network"
    )


def _exec_channel(db: Session, ws) -> tuple[list[str], str | None]:
    """Management exec argv prefix for the workstation, or (None, reason)."""
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    provider = ws.provider or "docker"
    if provider in ("manual", "ssh", "ssh_host"):
        # imported machines have no local container — manage over SSH with
        # their own stored credentials (platform key fallback), the same
        # channel authorized_keys grants use
        return ["__ssh__"], None
    if provider == "kubernetes":
        name = meta.get("k8s_name") or ws.name
        ns = meta.get("k8s_namespace") or "default"
        # kubeconfig of the infra provider that runs this workstation.
        # A Kubernetes workstation can only exist if something provisioned
        # it, so this branch is unreachable in Community Edition — but the
        # import is not, and would break the module at load time
        # (docs/modules/EDITIONS.md).
        from ...models.infra_v2 import InfraProvider
        from ..editions import ee_import

        engine = ee_import("infra.engine")
        if engine is None:
            return [], "this edition does not manage Kubernetes workstations"
        _build_target = engine._build_target

        prov = (
            db.query(InfraProvider).get(ws.infra_provider_id) if ws.infra_provider_id else None
        )
        if not prov:
            return [], "k8s workstation has no infra provider"
        target = _build_target(prov)
        if not target.kubeconfig:
            return [], "provider has no kubeconfig"
        import tempfile

        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        f.write(target.kubeconfig)
        f.close()
        return [
            "kubectl", "--kubeconfig", f.name, "-n", ns,
            "exec", f"deploy/{name}", "--",
        ], None
    # docker compose project convention from provisioning
    # the compose spec pins container_name (umbryx-ws-<pid>-<wsid>, or a
    # hash when that exceeds docker's 64-char limit) — the old
    # "<wsid>-workstation-1" guess matched nothing and every hook/PTY
    # install failed with "No such container" (found live on the EE stand)
    container = (meta or {}).get("container_name")
    if not container:
        # machines provisioned before the name was persisted in meta:
        # recompute it exactly like the provider does (umbryx-ws-<pid>-<wsid>,
        # hashed when it exceeds docker's 64-char limit)
        cand = f"umbryx-ws-{ws.project_id}-{ws.id}"
        if len(cand) > 64:
            import hashlib

            cand = f"umbryx-ws-{hashlib.sha256(cand.encode()).hexdigest()[:16]}"
        container = cand
    return ["docker", "exec", container], None


def _run(db: Session, ws, argv: list[str], script: str, timeout: int = 30) -> tuple[bool, str]:
    try:
        if argv == ["__ssh__"]:
            from ..ssh_exec import run_ssh_command
            from .pool import _ssh_config_for

            cfg = _ssh_config_for(ws, db)
            if not cfg:
                return False, "machine has no access address"
            r = run_ssh_command(cfg, script, timeout)
            if not r.get("ok"):
                return False, (r.get("stderr") or r.get("error") or "ssh failed")[:300]
            return True, (r.get("stdout") or "")[:300]
        r = subprocess.run(
            argv + ["sh", "-c", script],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode == 0, (r.stderr or r.stdout)[:300]
    except Exception as exc:
        return False, str(exc)[:300]


AUDIT_LOG_PATH = "$HOME/.umbryx/audit.log"


def install_hook(
    db: Session, ws, url: str = "", token: str = "", mode: str = "push"
) -> tuple[bool, str]:
    """Install the audit hook.

    mode=push: the machine POSTs each command to `url` (needs machine→
    platform connectivity). mode=pull: the hook only appends JSON lines to
    ~/.umbryx/audit.log and the platform reads them over SSH — works when
    the machine can't reach the platform at all (routed segments, NAT).
    """
    argv, reason = _exec_channel(db, ws)
    if reason:
        return False, reason
    if mode == "pull":
        hook = HOOK_PULL_TEMPLATE
    else:
        hook = HOOK_TEMPLATE.replace("__UMBRYX_URL__", url).replace("__UMBRYX_TOKEN__", token)
    # base64 transport: the hook contains $, quotes and newlines — inlining
    # it into a double-quoted shell string expands the variables AT INSTALL
    # TIME and json.dumps keeps \n literal, producing one giant broken line
    # in the rc (found live: .zshrc:259 'no such file or directory').
    # base64 has none of those characters — decode on the machine.
    payload_b64 = base64.b64encode(hook.encode()).decode()
    # Shell-aware install: the user's own rc (~/.zshrc / ~/.bashrc) is
    # writable without root and correct for their shell; /etc/bash.bashrc
    # only as a root fallback. Strip old blocks from all three so a
    # re-enable never duplicates the hook (the sed range also removes the
    # legacy single-line broken copies — they carry both markers).
    script = (
        f"RC=$HOME/.zshrc; [ -n \"$BASH_VERSION\" ] && RC=$HOME/.bashrc; "
        f"[ -w \"$RC\" ] || RC=/etc/bash.bashrc; "
        f"for f in $HOME/.zshrc $HOME/.bashrc /etc/bash.bashrc; do "
        f"sed -i '/{HOOK_BEGIN}/,/{HOOK_END}/d' \"$f\" 2>/dev/null; done; "
        f"printf '%s' {payload_b64} | base64 -d >> \"$RC\"; printf '\\n' >> \"$RC\"; "
        f"echo installed:$RC"
    )
    ok, out = _run(db, ws, argv, script)
    if not ok:
        return False, f"hook install failed: {out}"
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    meta["action_log_enabled"] = True
    meta["action_log_mode"] = mode
    if mode == "pull":
        meta.setdefault("action_log_offset", 0)
    ws.meta = meta
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(ws, "meta")
    db.commit()
    return True, "installed"


def remove_hook(db: Session, ws) -> tuple[bool, str]:
    argv, reason = _exec_channel(db, ws)
    if reason:
        return False, reason
    ok, out = _run(db, ws, argv, f"for f in $HOME/.zshrc $HOME/.bashrc /etc/bash.bashrc; do sed -i '/{HOOK_BEGIN}/,/{HOOK_END}/d' \"$f\" 2>/dev/null; done; true")
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    meta["action_log_enabled"] = False
    ws.meta = meta
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(ws, "meta")
    db.commit()
    return ok, "removed" if ok else f"removal failed: {out}"


def _timeline_event(db: Session, ws, action: WorkstationAction) -> None:
    """Mirror a workstation action into the project timeline (when the
    machine is project-bound) — same shape for every source: shell-hook,
    pull-harvest and platform executions."""
    if not ws.project_id:
        return
    from ..events import log_event

    # Secrets are masked in the timeline for EVERYONE (viewer and client
    # roles have timeline.read but must never see a password an operator
    # typed inline). The raw command stays in the actions feed /
    # session detail, gated by credentials.read_secret.
    from ..termtrack.redact import redact_command_secrets

    log_event(
        db,
        ws.project_id,
        action.username or "workstation",
        "workstation",
        "command",
        f"[{ws.name}] {redact_command_secrets(action.command)[:160]}",
        {"workstation_id": ws.id, "cwd": action.cwd, "source": action.source},
        ts=action.ts or None,
    )


def ingest_action(db: Session, ws, body: dict) -> WorkstationAction:
    action = WorkstationAction(
        id=new_id("wsa"),
        workstation_id=ws.id,
        pid=ws.project_id,
        username=(body.get("user") or "")[:120],
        command=(body.get("command") or "")[:4000],
        cwd=(body.get("cwd") or "")[:500],
        # SSH_CLIENT = "<client ip> <client port> <server port>": the port
        # + sshd VERBOSE fingerprint logs let an auditor attribute a shared
        # root session to the platform user whose key authenticated it.
        ssh_client=(body.get("ssh_client") or "")[:120],
        tty=(body.get("tty") or "")[:60],
        source="shell-hook",
        ts=ts_now(),
    )
    db.add(action)
    # termtrack: correlate into the terminal session (same tty) and
    # record a suspected nested-SSH hop when the command starts one.
    try:
        from ..termtrack.sessions import correlate_action, record_ssh_jump

        sess = correlate_action(db, ws, action)
        record_ssh_jump(db, sess, action.command, action.ts or ts_now())
    except Exception as exc:  # noqa: BLE001 — telemetry must never break ingest
        logger.warning("[ws-actions] session correlation failed: %s", exc)
    _timeline_event(db, ws, action)
    db.commit()
    try:
        attribute_ssh_sessions(db, ws, [action])
    except Exception as exc:  # noqa: BLE001 — attribution is best-effort
        logger.warning("[ws-actions] attribution %s failed: %s", ws.id, exc)
    _bcast_engagement(db, ws, [action])
    return action


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


def pull_actions(db: Session, ws, force: bool = False) -> int:
    """Pull new audit lines from a pull-mode machine over SSH and ingest
    them locally. Returns the number of new actions. Offset-based; a
    truncated/rotated file resets the offset."""
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    if not meta.get("action_log_enabled") or meta.get("action_log_mode") != "pull":
        return 0
    argv, reason = _exec_channel(db, ws)
    if reason:
        return 0
    offset = int(meta.get("action_log_offset") or 0)
    script = (
        f'F={AUDIT_LOG_PATH}; [ -f "$F" ] || exit 0; '
        f"S=$(wc -c < \"$F\" 2>/dev/null | tr -d ' '); "
        f'[ "$S" -lt {offset} ] && OFFSET=0 || OFFSET={offset}; '
        f'tail -c +$((OFFSET + 1)) "$F"; echo "__SIZE__$S"'
    )
    if argv == ["__ssh__"]:
        from ..ssh_exec import run_ssh_command
        from .pool import _ssh_config_for

        cfg = _ssh_config_for(ws, db)
        if not cfg:
            return 0
        r = run_ssh_command(cfg, script, 25)
        if not r.get("ok"):
            return 0
        out = r.get("stdout") or ""
    else:
        import subprocess as sp

        rp = sp.run(argv + ["sh", "-c", script], capture_output=True, text=True, timeout=30)
        if rp.returncode != 0:
            return 0
        out = rp.stdout or ""

    if "__SIZE__" not in out:
        return 0
    body, size_s = out.rsplit("__SIZE__", 1)
    try:
        size = int(size_s.strip())
    except ValueError:
        return 0

    new_offset = offset
    ingested = 0
    rows: list[WorkstationAction] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        action = WorkstationAction(
            id=new_id("wsa"),
            workstation_id=ws.id,
            pid=ws.project_id,
            username=(entry.get("user") or "")[:120],
            command=(entry.get("command") or "")[:4000],
            cwd=(entry.get("cwd") or "")[:500],
            ssh_client=(entry.get("ssh_client") or "")[:120],
            tty=(entry.get("tty") or "")[:60],
            source="shell-hook",
            ts=entry.get("ts") or ts_now(),
        )
        db.add(action)
        rows.append(action)
        ingested += 1
    if ingested:
        # attribute FIRST (ssh session ↔ profile-key fingerprint → the
        # platform user who typed it), THEN mirror to the timeline so the
        # event carries the operator, not the shared local account
        db.commit()
        try:
            attribute_ssh_sessions(db, ws, rows)
        except Exception as exc:  # noqa: BLE001 — attribution is best-effort
            logger.warning("[ws-actions] attribution %s failed: %s", ws.id, exc)
        # termtrack: pull-mode rows join their sessions too (jumps +
        # session state), same best-effort contract as attribution
        try:
            from ..termtrack.sessions import correlate_action, record_ssh_jump

            for action in rows:
                sess = correlate_action(db, ws, action)
                record_ssh_jump(db, sess, action.command, action.ts or ts_now())
            db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[ws-actions] session correlation %s failed: %s", ws.id, exc)
        for action in rows:
            _timeline_event(db, ws, action)
        db.commit()
        _bcast_engagement(db, ws, rows)
    new_offset = size
    if new_offset != offset or ingested:
        meta["action_log_offset"] = new_offset
        ws.meta = meta
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(ws, "meta")
        db.commit()
    return ingested


def harvest_pull_machines(db: Session) -> int:
    """Pull new audit lines from EVERY enabled pull-mode machine.

    Called by the periodic background loop (main._ws_action_pull_loop) so
    actions reach the platform without anybody opening the feed."""
    from ...models import OperatorWorkstation

    total = 0
    for ws in (
        db.query(OperatorWorkstation).filter(OperatorWorkstation.is_pool.is_(True)).all()
    ):
        meta = ws.meta if isinstance(ws.meta, dict) else {}
        if meta.get("action_log_enabled") and meta.get("action_log_mode") == "pull":
            try:
                total += pull_actions(db, ws)
            except Exception as exc:  # noqa: BLE001 — one machine must not stop the rest
                logger.warning("[ws-actions] pull %s failed: %s", ws.id, exc)
    return total


def _user_fingerprints(db: Session) -> dict[str, str]:
    """SHA256 fingerprint of every profile key → platform username."""
    from ...models import User, UserSshKey

    out: dict[str, str] = {}
    for key in db.query(UserSshKey).all():
        from .pool import fingerprint_of

        fp = fingerprint_of(key.public_key)
        if not fp:
            continue
        user = db.query(User).filter(User.id == key.user_id).first()
        if user:
            out[fp] = user.username
    return out


def attribute_ssh_sessions(db: Session, ws, actions: list[WorkstationAction]) -> int:
    """Replace the local OS username with the PLATFORM user who actually
    typed the command.

    Shared-root problem: everyone logs in as root/administrator, so the
    hook only reports the local user. But operators authenticate with
    their own PROFILE keys — sshd logs 'Accepted publickey for <local>
    from <ip> port <port> ssh2: ED25519 SHA256:<fp>'. The port comes from
    the action's SSH_CLIENT; matching the fingerprint against profile
    keys names the operator. One SSH round per batch."""
    pending = [a for a in actions if a.ssh_client and len(a.ssh_client.split()) >= 2]
    if not pending:
        return 0
    fps = _user_fingerprints(db)
    if not fps:
        return 0

    ip_port = {}
    for a in pending:
        parts = a.ssh_client.split()
        ip_port[parts[0]] = parts[1]

    argv, reason = _exec_channel(db, ws)
    if reason:
        return 0
    matchers = " | ".join(
        f"grep 'from {ip} port {port} '" for ip, port in ip_port.items()
    )
    script = (
        "{ journalctl -q --no-pager --since=-24h 2>/dev/null; "
        "sudo -n journalctl -q --no-pager --since=-24h 2>/dev/null; "
        "cat /var/log/auth.log /var/log/secure 2>/dev/null; } "
        f"| grep 'Accepted publickey' | {matchers} | tail -50; true"
    )
    if argv == ["__ssh__"]:
        from ..ssh_exec import run_ssh_command
        from .pool import _ssh_config_for

        cfg = _ssh_config_for(ws, db)
        if not cfg:
            return 0
        r = run_ssh_command(cfg, script, 25)
        if not r.get("ok"):
            return 0
        out = r.get("stdout") or ""
    else:
        import subprocess as sp

        rp = sp.run(argv + ["sh", "-c", script], capture_output=True, text=True, timeout=30)
        if rp.returncode != 0:
            return 0
        out = rp.stdout or ""

    # "Accepted publickey for root from 172.16.90.1 port 27982 ssh2:
    #  ED25519 SHA256:abcdef"
    fp_by_port: dict[str, str] = {}
    import re as _re

    for m in _re.finditer(
        r"from\s+(\S+)\s+port\s+(\d+)\s+ssh2:\s+\S+\s+(SHA256:\S+)", out
    ):
        fp_by_port[m.group(2)] = m.group(3)

    attributed = 0
    for a in pending:
        port = a.ssh_client.split()[1]
        fp = fp_by_port.get(port)
        username = fps.get(fp or "")
        if username and username != a.username:
            a.username = username
            attributed += 1
    if attributed:
        db.commit()
    return attributed


def extract_target_ips(command: str) -> set[str]:
    """Literal IPv4 targets in a command line (exact IPs, no CIDRs)."""
    ips = set()
    for match in IP_RE.findall(command or ""):
        if "/" not in match:
            ips.add(match)
    return ips


def _bcast_engagement(db: Session, ws, actions: list[WorkstationAction]) -> None:
    """Announce that shell activity changed who is engaged on a host.

    Workstation activity is one of the signals behind the deconfliction
    engagement map (routers/deconfliction.py), but nothing was broadcast when
    an action landed, so the chip on the network map and the host panel only
    picked it up on their next 30s poll — which reads as "only after a page
    reload". Best-effort: a failure here must never fail the action log.
    """
    pid = getattr(ws, "project_id", None)
    if not pid:
        return
    try:
        ips: set[str] = set()
        for action in actions:
            ips |= extract_target_ips(action.command)
        if not ips:
            return
        from ...models import Host

        host_ids = [
            row.id
            for row in db.query(Host)
            .filter(Host.pid == pid, Host.ip.in_(ips), Host.deleted_at.is_(None))
            .all()
        ]
        if not host_ids:
            return
        from ..events import bcast

        bcast(pid, "host", "engagement", {"host_ids": host_ids, "workstation_id": ws.id})
    except Exception as exc:  # noqa: BLE001 — never break logging over a bcast
        logger.warning("[ws-actions] engagement bcast for %s failed: %s", ws.id, exc)



def log_platform_action(
    db: Session,
    ws_id: str,
    pid: str | None,
    command: str,
    actor: str,
    exit_code: int = -1,
    origin: str = "platform",
) -> WorkstationAction | None:
    """Record an action the PLATFORM executed on a workstation (via its
    ws:<id> SSH-executor target) into that machine's action log — so the
    Platform Ops feed shows run_command/attacker-exec traffic too, not
    only interactive shell-hook sessions."""
    from ...models import OperatorWorkstation

    ws = db.query(OperatorWorkstation).filter(OperatorWorkstation.id == ws_id).first()
    if not ws:
        return None
    action = WorkstationAction(
        id=new_id("wsa"),
        workstation_id=ws.id,
        pid=pid or ws.project_id,
        username=actor[:120],
        command=(command or "")[:4000],
        cwd="",
        ssh_client="",
        tty="",
        source=f"platform:{origin}",
        ts=ts_now(),
        exit_code=exit_code,
    )
    db.add(action)
    _timeline_event(db, ws, action)
    db.commit()
    try:
        attribute_ssh_sessions(db, ws, [action])
    except Exception as exc:  # noqa: BLE001 — attribution is best-effort
        logger.warning("[ws-actions] attribution %s failed: %s", ws.id, exc)
    _bcast_engagement(db, ws, [action])
    return action
