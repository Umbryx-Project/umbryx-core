"""Segment a PTY recording into per-command chunks.

The stream carries our OSC-7770 markers (one per executed command, from
the extended hook). Segmentation = split on markers; the bytes after a
marker up to the next one are that command's output echo + result.

Control sequences are stripped for parsing, but a lightly-scrubbed raw
view is kept for the session viewer (operators need the real terminal
look-back; parsers need clean text).
"""

from __future__ import annotations

import base64
import re

# OSC 7770 ; umbryx ; cmd ; <b64>
OSC_MARKER_RE = re.compile(r"\x1b\]7770;umbryx;cmd;([A-Za-z0-9+/=]*)\x07")

_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)
_CR_LF_RE = re.compile(r"\r?\n")


def decode_marker(b64: str) -> str:
    try:
        return base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — a malformed marker must not kill the stream
        return ""


def strip_ansi(text: str) -> str:
    """Remove CSI/OSC/other escape sequences and normalize newlines."""
    return _CR_LF_RE.sub("\n", _ANSI_RE.sub("", text))


def segment_stream(text: str) -> list[dict]:
    """Split a (possibly incremental) PTY stream into command segments.

    Returns [{"command", "output"}] — the marker's command with the
    bytes that followed it (ANSI-stripped, tail-capped by the caller).
    A trailing chunk before the first marker (banner, pre-hook output)
    is skipped: it has no command to attribute to.
    """
    out: list[dict] = []
    pos = 0
    current: dict | None = None
    for m in OSC_MARKER_RE.finditer(text):
        if current is not None:
            current["output"] += text[pos : m.start()]
            out.append(current)
        command = decode_marker(m.group(1))
        current = {"command": command, "output": ""}
        pos = m.end()
    if current is not None:
        current["output"] += text[pos:]
        out.append(current)

    for seg in out:
        # normalize + cap at a size that is plenty for parsing while
        # keeping the stored segment bounded
        seg["output"] = strip_ansi(seg["output"])[:20_000]
    return out
