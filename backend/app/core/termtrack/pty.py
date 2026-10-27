"""PTY recorder: install a `script(1)` wrapper on the workstation and
harvest the recordings.

Why script(1) and not a shell-level hook: the existing hook sees command
*lines* only — nothing typed inside an interactive tool or a nested SSH
session ever reaches it. `script` sits under the whole shell as a pty
master and records the raw stream; util-linux ships it everywhere the
management channel can reach.

Design:
- /etc/profile.d/umbryx-termtrack.sh re-execs the login shell under
  `script -qef <log> -c <shell>` when the session is interactive and
  not already wrapped (marker env var). Idempotent, same marker-block
  convention as the action hook.
- The recording header line carries the tty + start ts (correlation
  key), written by the wrapper itself before exec.
- The action hook is extended to emit an OSC-7770 marker carrying the
  base64 command line into the terminal right before execution — the
  marker lands in the recording, giving per-command segmentation with
  zero timing inference. (The marker is invisible to the operator:
  terminals ignore unknown OSC sequences.)
- Harvest is pull-only over the existing channel with a per-file offset
  in workstation meta (rotation-safe: files are named by session start
  ts; a vanished file resets its offset).
"""

from __future__ import annotations

import logging
import re

from sqlalchemy.orm import Session

from ..utils import ts_now

logger = logging.getLogger(__name__)

TERM_BEGIN = "# UMBRYX-TERMTRACK-BEGIN"
TERM_END = "# UMBRYX-TERMTRACK-END"
PTY_DIR = "$HOME/.umbryx/pty"
OFFLINE_META_KEY = "pty_offsets"

PROFILE_TEMPLATE = f"""{TERM_BEGIN}
# Umbryx terminal telemetry: record the login shell's PTY stream.
# Re-exec only interactive, unwrapped login shells — nested/`script`
# invocations and non-tty contexts pass through untouched.
if [ -n "$PS1" ] && [ -t 0 ] && [ -z "$UMBRYX_PTY_WRAP" ] && \\
   [ -z "$UMBRYX_SKIP_PTY" ]; then
  export UMBRYX_PTY_WRAP=1
  _umbryx_dir={PTY_DIR}
  mkdir -p "$_umbryx_dir" 2>/dev/null || {{ unset UMBRYX_PTY_WRAP; return 0 2>/dev/null || exit 0; }}
  _umbryx_log="$_umbryx_dir/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  printf '{{"tty":"%s","ts":"%s","user":"%s","ssh_client":"%s"}}\\n' \\
    "$(tty 2>/dev/null || echo '')" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
    "${{USER:-$(id -un)}}" "${{SSH_CLIENT:-}}" > "$_umbryx_log"
  # 700 for the DIR (x bit — entering it), 600 for the log file:
  # chmod 600 on the directory itself made it un-enterable and every
  # session died at the first redirect (found live on the range box).
  chmod 700 "$_umbryx_dir" 2>/dev/null; chmod 600 "$_umbryx_log" 2>/dev/null
  if command -v script >/dev/null 2>&1; then
    exec script -qef "$_umbryx_log" -c "$SHELL"
  fi
  unset UMBRYX_PTY_WRAP
fi
{TERM_END}"""

# The hook extension: OSC-7770 with a base64 command, emitted right
# before the command runs. Unknown OSC sequences are dropped by every
# terminal we care about — the operator never sees it, the recording
# always gets it.
HOOK_MARKER_FUNC = """
__umbryx_mark() {
  # OSC 7770 ; umbryx ; cmd ; <b64 of command line>
  local b; b=$(printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 2>/dev/null)
  [ -n "$b" ] && printf '\\033]7770;umbryx;cmd;%s\\007' "$b"
}
"""


def install_pty_recorder(db: Session, ws) -> tuple[bool, str]:
    """Install (or refresh) the profile wrapper via the workstation's
    management channel. Returns (ok, reason).

    Shell-aware targets (found live on an SSH-registered range machine):
    /etc/profile.d needs root — an unprivileged management user can't
    write there, and the old installer reported success from the SSH
    transport alone while the file never appeared. Now the block is
    tried against profile.d first (container workstations, root exec)
    and falls back to the user's own rc (~/.zshrc / ~/.bashrc — the same
    writable-target trick the action hook uses), carries the payload in
    base64 (marker-delimited, idempotent re-install), and VERIFIES the
    write by reading the marker back.
    """
    import base64 as _b64

    from ..workstation.actions import _exec_channel

    argv, reason = _exec_channel(db, ws)
    if reason:
        return False, reason

    payload_b64 = _b64.b64encode(PROFILE_TEMPLATE.encode()).decode()
    # POSIX-clean: no brace groups / case-in-command — the management
    # user's login shell interprets this and may be zsh (found live).
    script = (
        "umask 022; "
        # idempotency: strip previous blocks everywhere we may have written
        f"for f in /etc/profile.d/umbryx-termtrack.sh $HOME/.zshrc $HOME/.bashrc; do "
        f"[ -f \"$f\" ] && sed -i '/{TERM_BEGIN}/,/{TERM_END}/d' \"$f\" 2>/dev/null; done; true; "
        # target priority: profile.d (root) → rc of the user's OWN shell
        "T=/etc/profile.d/umbryx-termtrack.sh; "
        "mkdir -p /etc/profile.d 2>/dev/null; "
        f"printf '%s' {payload_b64} | base64 -d > \"$T\" 2>/dev/null; "
        "[ -s \"$T\" ] || T=$(if echo \"$SHELL\" | grep -q zsh; then echo $HOME/.zshrc; else echo $HOME/.bashrc; fi); "
        f"printf '%s' {payload_b64} | base64 -d >> \"$T\"; printf '\\n' >> \"$T\"; "
        # verify: the marker must read back from the file we chose
        f"grep -q '{TERM_BEGIN}' \"$T\" 2>/dev/null && echo installed:\"$T\" || echo failed:\"$T\""
    )
    import subprocess

    if argv == ["__ssh__"]:
        from ..ssh_exec import run_ssh_command
        from ..workstation.pool import _ssh_config_for

        cfg = _ssh_config_for(ws, db)
        if not cfg:
            return False, "no ssh config for workstation"
        r = run_ssh_command(cfg, script, 30)
        # transport ok AND command exit 0 AND marker echoed — all three
        if not r.get("ok") or r.get("exit_code", 0) != 0 or "installed:" not in (r.get("stdout") or ""):
            return False, (r.get("stdout") or r.get("stderr") or r.get("error") or "install failed")[:200]
        target = (r.get("stdout") or "").split("installed:", 1)[-1].strip().strip('"')
        meta = dict(ws.meta) if isinstance(ws.meta, dict) else {}
        meta["pty_install_target"] = target
        from sqlalchemy.orm.attributes import flag_modified

        ws.meta = meta
        flag_modified(ws, "meta")
        db.commit()
        return True, f"installed → {target}"
    try:
        out = subprocess.run(argv + ["sh", "-c", script], capture_output=True, text=True, timeout=60)
        if out.returncode != 0 or "installed:" not in (out.stdout or ""):
            return False, (out.stdout or out.stderr or "exec failed")[:200]
        return True, f"installed → {(out.stdout or '').split('installed:', 1)[-1].strip()}"
    except Exception as exc:  # noqa: BLE001 — reason string for the UI
        return False, str(exc)[:200]


_OFF_PLACEHOLDER = "__OFF__"
_FILE_PLACEHOLDER = "__FILE__"


# one "<size> <name>" pair per line — wc's own newline would otherwise
# split the pair across two lines and the parser would see nothing
_LIST_TEMPLATE = (
    "umask 077; "
    f"D={PTY_DIR}; [ -d \"$D\" ] || exit 0; "
    "for f in \"$D\"/*; do [ -f \"$f\" ] && printf '%s %s\\n' \"$(wc -c < \"$f\" | tr -d ' ')\" \"$(basename \"$f\")\"; done; true"
)

_PULL_TEMPLATE = (
    "umask 077; "
    f"D={PTY_DIR}; F=\"$D/{_FILE_PLACEHOLDER}\"; [ -f \"$F\" ] || {{ echo __GONE__; exit 0; }}; "
    # f-string on purpose: both placeholders must interpolate to their
    # bare tokens (__FILE__ / __OFF__) so the .replace() calls in
    # harvest_pty match them
    f"tail -c +{_OFF_PLACEHOLDER} \"$F\"; true"
)


def _run_channel(db: Session, ws, script: str, timeout: int = 25) -> str | None:
    from ..workstation.actions import _exec_channel

    argv, reason = _exec_channel(db, ws)
    if reason:
        return None
    if argv == ["__ssh__"]:
        from ..ssh_exec import run_ssh_command
        from ..workstation.pool import _ssh_config_for

        cfg = _ssh_config_for(ws, db)
        if not cfg:
            return None
        r = run_ssh_command(cfg, script, timeout)
        return r.get("stdout") if r.get("ok") else None
    import subprocess

    try:
        out = subprocess.run(argv + ["sh", "-c", script], capture_output=True, text=True, timeout=timeout + 15)
        return out.stdout if out.returncode == 0 else None
    except Exception:  # noqa: BLE001
        return None


def harvest_pty(db: Session, ws, max_files: int = 20, max_bytes: int = 400_000) -> dict:
    """Pull new PTY bytes for the workstation. Returns stats. Offsets
    live in ws.meta[OFFLINE_META_KEY] = {filename: offset}."""
    from sqlalchemy.orm.attributes import flag_modified

    meta = ws.meta if isinstance(ws.meta, dict) else {}
    offsets: dict = dict(meta.get(OFFLINE_META_KEY) or {})

    listing = _run_channel(db, ws, _LIST_TEMPLATE) or ""
    files: list[tuple[str, int]] = []
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            files.append((parts[1], int(parts[0])))
    if not files:
        return {"files": 0, "bytes": 0}

    files.sort()
    stats = {"files": 0, "bytes": 0}
    tails: dict = dict(meta.get("pty_tails") or {})
    for name, size in files[-max_files:]:
        off = int(offsets.get(name, 0))
        if size <= off:
            continue
        script = _PULL_TEMPLATE.replace(_FILE_PLACEHOLDER, name).replace(_str_off(), str(off + 1))
        chunk = _run_channel(db, ws, script, timeout=30)
        if chunk is None:
            continue
        if chunk.strip() == "__GONE__":
            offsets.pop(name, None)
            tails.pop(name, None)
            continue
        # tail -c +N is 1-based; empty means nothing new survived quoting
        if chunk:
            new_tail = _on_chunk(db, ws, name, off, chunk, tails.get(name, ""))
            tails[name] = new_tail
            offsets[name] = off + len(chunk.encode("utf-8", "replace"))
            stats["files"] += 1
            stats["bytes"] += len(chunk.encode("utf-8", "replace"))
    meta["pty_tails"] = tails

    meta[OFFLINE_META_KEY] = offsets
    ws.meta = meta
    flag_modified(ws, "meta")
    db.commit()
    return stats


def _str_off() -> str:
    return _OFF_PLACEHOLDER



_HEADER_RE = re.compile(r'^\{"tty":"([^"]*)","ts":"([^"]*)","user":"([^"]*)","ssh_client":"([^"]*)"\}')


def _on_chunk(db: Session, ws, name: str, offset: int, chunk: str, tail: str = "") -> str:
    """Feed harvested bytes through the full pipeline: session lookup,
    per-command segmentation, actions, observations, auto-apply.

    Returns the new unconsumed tail (output of a still-running command
    that no next marker has closed yet)."""
    from ...models.workstation_session import WorkstationSession
    from .ingest import ingest_pty_bytes
    from .sessions import get_or_create_session

    header = None
    if offset == 0:
        first_line, _, _ = chunk.partition("\n")
        m = _HEADER_RE.match(first_line.strip())
        if m:
            header = {"tty": m.group(1), "ts": m.group(2), "user": m.group(3), "ssh_client": m.group(4)}

    tty = (header or {}).get("tty", "")
    sess = (
        db.query(WorkstationSession)
        .filter(
            WorkstationSession.workstation_id == ws.id,
            WorkstationSession.pty_log == name,
        )
        .first()
    )
    if sess is None:
        sess = get_or_create_session(
            db, ws, tty,
            (header or {}).get("user", ""),
            (header or {}).get("ssh_client", ""),
            (header or {}).get("ts") or ts_now(),
        )
        sess.pty_log = name
        db.flush()
        if ws.project_id:
            from ..events import log_event

            log_event(
                db, ws.project_id, sess.username or "workstation",
                "workstation", "session_started",
                f"[{ws.name}] terminal session started" + (f" ({tty})" if tty else ""),
                {"session_id": sess.id, "workstation": ws.name},
                ts=sess.started_at,
            )

    stats, new_tail = ingest_pty_bytes(db, ws, sess, name, chunk, tail)

    try:
        cur = int(sess.pty_bytes or "0")
    except ValueError:
        cur = 0
    sess.pty_bytes = str(cur + len(chunk.encode("utf-8", "replace")))
    if stats["commands"]:
        from ..events import log_event

        log_event(
            db, ws.project_id, sess.username or "workstation",
            "workstation", "pty_batch",
            f"[{ws.name}] {stats['commands']} command(s), "
            f"{stats['observations']} observation(s), {stats['applied']} applied",
            {"session_id": sess.id, "workstation": ws.name},
        )
    return new_tail
