#!/bin/sh
# Pool SSH machine entrypoint: install the platform key from env, run sshd.
set -e

SSH_USER="${UMBRYX_SSH_USER:-root}"
HOME_DIR="$(eval echo "~$SSH_USER")"
mkdir -p "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"

if [ -n "$UMBRYX_SSH_KEY" ]; then
  printf '%s\n' "$UMBRYX_SSH_KEY" > "$HOME_DIR/.ssh/authorized_keys"
  chmod 600 "$HOME_DIR/.ssh/authorized_keys"
  chown "$SSH_USER" "$HOME_DIR/.ssh/authorized_keys" 2>/dev/null || true
fi

# keep the file writable so the platform can append/revoke user keys over SSH
touch "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"

exec /usr/sbin/sshd -D -e
