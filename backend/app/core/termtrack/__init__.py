"""Terminal telemetry: PTY recording, session correlation, output capture.

Layered on top of the existing shell hooks (core/workstation/actions.py):

- hooks stay the command *event* source (exact command lines, exit
  attribution, push or pull);
- a `script(1)` wrapper installed via /etc/profile.d records the full
  PTY stream to a file; the extended hook emits an OSC-7770 marker with
  the base64 command line right before execution, so the marker lands
  in the recording itself — segmentation needs no timing files and no
  guessing, and correlation between the two sources is the tty;
- the harvester pulls both over the same management channel the hooks
  already use (docker exec / kubectl exec / ssh), with offsets kept in
  the workstation's meta, exactly like the pull-mode hook harvest.
"""

from .enrich import apply_observation, apply_pending_for_project
from .observations import create_observations
from .pty import harvest_pty, install_pty_recorder
from .segment import OSC_MARKER_RE, decode_marker, segment_stream
from .sessions import (
    SESSION_IDLE_MINUTES,
    close_idle_sessions,
    correlate_action,
    get_or_create_session,
    record_ssh_jump,
)

__all__ = [
    "SESSION_IDLE_MINUTES",
    "close_idle_sessions",
    "correlate_action",
    "get_or_create_session",
    "record_ssh_jump",
    "install_pty_recorder",
    "harvest_pty",
    "OSC_MARKER_RE",
    "decode_marker",
    "segment_stream",
    "create_observations",
    "apply_observation",
    "apply_pending_for_project",
]
