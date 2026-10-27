"""Secret redaction for operator commands.

Commands typed in a terminal routinely carry inline secrets: tool
passwords (`hydra -p`, `nxc -p`), NTLM hashes (`-hashes :…`),
connection strings (`impacket-psexec DOM\\user:pass@10.0.0.5`), tokens.
The raw command stays in the audit trail and the actions feed for those
entitled to secrets, but every broader surface (timeline, sessions,
observation provenance) shows a masked form — a viewer or a client role
must never see a password just because an operator typed it.

Port-vs-password disambiguation: `-p 445` (nmap/ssh port) stays,
`-p S3cret!` is masked — purely numeric/range values are ports in every
tool we match; passwords that are purely numeric are a loss we accept
(see tests).
"""

from __future__ import annotations

import re

REDACTED = "***REDACTED***"

_PORTISH = re.compile(r"^\d+([-,]\d+)*$")

# long flags whose value is a secret by the flag's own name
_LONG_SECRET_FLAGS = re.compile(
    r"(?i)(?P<flag>--(?:password|passwd|pass|pwd|secret|token|api[-_]?key|apikey|"
    r"hashes?|ntlm|kerberos|auth|pwd-hash|shared[-_]?key))"
    r"(?P<sep>[=\s])(?P<q>['\"]?)(?P<val>\S+?)(?P=q)"
)

# impacket-style short flags: -H / -hashes take hash material. Only
# masked when the value LOOKS like hashes (`:LM:NT`, hex) — curl's -H
# takes an arbitrary header and must survive.
_SHORT_HASH_FLAGS = re.compile(
    r"(?i)(?P<flag>-H|-hashes)\s+(?P<val>:?[0-9a-fA-F:]{16,})"
)

# short password flags (hydra/nxc/etc.) — masked when not port-like
_SHORT_PASS_QUOTED = re.compile(
    r"(?P<flag>-p|--pass)\s+(?P<q>['\"])(?P<val>[^'\"]+)(?P=q)", re.IGNORECASE
)
_SHORT_PASS_BARE = re.compile(r"(?P<flag>-p|--pass)\s+(?P<val>\S+)", re.IGNORECASE)

# URL userinfo: scheme://user:pass@host
_URL_USERINFO = re.compile(r"(?P<scheme>https?|ftp|ssh|rdp)://\S+?:\S+?@")

# impacket connection strings: DOM\user:pass@target or user:pass@target
# (the whole identity part before @ is sensitive: password inside)
_CONN_STRING = re.compile(
    r"(?<![\w.-])(?P<ident>[A-Za-z0-9.$_-]{1,32}(?:\\[A-Za-z0-9.$_-]{1,32})?"
    r":[^\s@/]{1,128})@(?=[A-Za-z0-9.\[])"
)

# standalone hash/blob material (NTLM, Kerberos tickets, tokens)
_BLOB = re.compile(r"\b[A-Fa-f0-9]{32,}\b|\b[A-Za-z0-9+/]{32,}={0,2}\b")

# Authorization headers / assignment forms
_AUTH_HEADER = re.compile(
    r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)(\S+)"
)
_SECRET_ASSIGN = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:password|passwd|secret|token|api_?key))\s*[:=]\s*(\S+)"
)

_KERB_HASH = re.compile(r"\$krb5[a-z0-9]*\$[^$\s]+\$[^$\s]+\$[^$\s]+\$[^$\s]+")


def redact_command_secrets(command: str) -> str:
    if not command:
        return command
    out = command

    out = _KERB_HASH.sub(REDACTED, out)
    out = _URL_USERINFO.sub(lambda m: f"{m.group('scheme')}://{REDACTED}@", out)

    def _long(m: re.Match) -> str:
        return f"{m.group('flag')}{m.group('sep')}{m.group('q')}{REDACTED}{m.group('q')}"

    out = _LONG_SECRET_FLAGS.sub(_long, out)
    out = _SHORT_HASH_FLAGS.sub(lambda m: f"{m.group('flag')} {REDACTED}", out)

    def _short(m: re.Match) -> str:
        val = m.group("val")
        if _PORTISH.match(val):
            return m.group(0)  # -p 445 / -p 1-65535 — a port
        q = m.groupdict().get("q") or ""
        return f"{m.group('flag')} {q}{REDACTED}{q}"

    out = _SHORT_PASS_QUOTED.sub(_short, out)
    out = _SHORT_PASS_BARE.sub(_short, out)

    def _conn(m: re.Match) -> str:
        ident = m.group("ident")
        # keep the identity visible when it carries no secret part
        if ":" not in ident.split("\\")[-1]:
            return m.group(0)
        dom, _, rest = ident.rpartition("\\")
        user, _, _secret = rest.partition(":")
        return f"{dom + chr(92) if dom else ''}{user}:{REDACTED}@"

    out = _CONN_STRING.sub(_conn, out)

    out = _AUTH_HEADER.sub(lambda m: m.group(1) + REDACTED, out)
    out = _SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _BLOB.sub(REDACTED, out)
    return out


def can_view_command_secrets(db, user, pid) -> bool:
    """Whether this user may see raw (unmasked) operator commands in the
    project — the same entitlement that reveals credential secrets."""
    from ..access import check_pid_access
    from ..enums import UserRole

    if user.role == UserRole.PLATFORM_ADMIN.value:
        return True
    try:
        check_pid_access(db, pid, user, "credentials.read_secret")
        return True
    except Exception:  # noqa: BLE001 — AppError means "no"
        return False
