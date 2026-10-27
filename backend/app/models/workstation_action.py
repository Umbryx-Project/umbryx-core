"""Workstation operator-action audit log."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text

from ..database import Base


class WorkstationAction(Base):
    """A command an operator executed inside a workstation shell.

    Recorded by a bash DEBUG-trap hook injected over the platform's
    management channel (docker exec / kubectl exec) — the workstation
    POSTs each command with a per-workstation token. Serves two masters:

    - audit trail: what every operator actually ran, for the engagement
      report and post-incident review
    - deconfliction: recent commands parsed for target IPs feed the
      automatic engagement map (source 'ws') — someone actively typing
      nmap/smbclient against a host is the strongest busy-signal there is
    """

    __tablename__ = "workstation_actions"

    id = Column(String, primary_key=True)
    workstation_id = Column(
        String, ForeignKey("operator_workstations.id", ondelete="CASCADE"), nullable=False
    )
    # correlated terminal session (same tty) — see WorkstationSession
    session_id = Column(String, ForeignKey("workstation_sessions.id", ondelete="SET NULL"), nullable=True)
    pid = Column(String, nullable=True, index=True)
    username = Column(String, nullable=False, default="")
    command = Column(Text, nullable=False, default="")
    cwd = Column(String, nullable=False, default="")
    # client ip:port from $SSH_CLIENT — attribution material for shared
    # accounts (correlatable with sshd "Accepted publickey ... SHA256:fp")
    ssh_client = Column(String, nullable=False, default="", server_default="")
    tty = Column(String, nullable=False, default="", server_default="")
    source = Column(String, nullable=False, default="shell-hook")
    # platform-originated actions (run_command / attacker-exec through the
    # machine's ws:<id> executor target) carry the command's exit code
    exit_code = Column(Integer, nullable=True)
    ts = Column(String, nullable=False)

    __table_args__ = (
        Index("ix_ws_actions_ws_ts", "workstation_id", "ts"),
        Index("ix_ws_actions_pid_ts", "pid", "ts"),
    )
