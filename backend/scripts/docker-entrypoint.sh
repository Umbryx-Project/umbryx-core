#!/bin/sh
# Container entrypoint — runs as root, fixes ownership of the runtime data
# dir, then drops to the unprivileged app user before exec'ing the real
# command. Needed because /data is a host bind mount (see docker-compose.yml
# comment on the backend volume): the first `docker compose up` on a host
# where ./data doesn't exist yet has Docker create it as root:root, which
# the non-root `umbryx` user then can't write into — previously this
# required a manual `docker exec ... chown` before the stack would work.
set -e

APP_USER="umbryx"
DATA_DIR="${UMBRYX_DATA_DIR:-/data}"

fix_owner() {
    # Idempotency / startup-cost guard: only pay for a recursive chown when
    # a path's own top-level ownership is actually wrong. On every run
    # after the first (or on a host where the mount was already correct)
    # this is a single stat call, not a walk of however much has
    # accumulated in the volume (uploads, loot, cracked-cred output...).
    path="$1"
    current_uid="$(stat -c '%u' "$path")"
    current_gid="$(stat -c '%g' "$path")"
    if [ "$current_uid" != "$APP_UID" ] || [ "$current_gid" != "$APP_GID" ]; then
        echo "docker-entrypoint: $path is owned by ${current_uid}:${current_gid}, expected ${APP_UID}:${APP_GID} — fixing (recursive chown)"
        chown -R "${APP_UID}:${APP_GID}" "$path"
    fi
}

if [ "$(id -u)" = "0" ]; then
    APP_UID="$(id -u "$APP_USER")"
    APP_GID="$(id -g "$APP_USER")"

    mkdir -p "$DATA_DIR"
    fix_owner "$DATA_DIR"

    # docker-compose.yml (dev) bind-mounts the whole $DATA_DIR as one host
    # path, so the check above is the whole story there. docker-
    # compose.prod.yml instead mounts separate *named* volumes at
    # $DATA_DIR/uploads and $DATA_DIR/plugins — each is its own mount
    # point with its own ownership, independent of $DATA_DIR itself (which
    # in that topology is just an empty dir baked into the image, always
    # already owned by the app user). Check each immediate child
    # independently rather than assuming a fix at the top covers them.
    for child in "$DATA_DIR"/*/; do
        [ -d "$child" ] || continue
        fix_owner "${child%/}"
    done

    # setpriv only changes the process's real/effective uid+gid — it does
    # NOT touch HOME, which stays whatever this root shell inherited
    # (/root). Left alone, the app process runs as uid 1000 with
    # HOME=/root: harmless until something does a HOME-relative lookup —
    # e.g. libpq's default client-certificate path
    # ($HOME/.postgresql/postgresql.crt), which then resolves to a path
    # uid 1000 can't read and fails closed with "Permission denied" on
    # every sslmode=require/prefer connection. Found live via
    # core/ha_status.py's monitor connection. Set HOME to the app user's
    # real home directory so every HOME-relative lookup in the app process
    # resolves correctly, instead of chasing this one file at a time.
    export HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"

    # exec, not a background/wait pattern: setpriv replaces this shell as
    # PID 1, so SIGTERM from `docker stop` reaches the actual app process
    # directly instead of being swallowed by a wrapper script.
    exec setpriv --reuid "$APP_UID" --regid "$APP_GID" --init-groups "$@"
fi

# Already running as a non-root user (e.g. an operator override of `user:`
# in compose, or a rebuild off a different base) — nothing to fix, just run.
exec "$@"
