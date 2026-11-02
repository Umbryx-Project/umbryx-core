#!/usr/bin/env bash
# Postgres-CI (track C, 2026-10-09): run the backend test suite against a real
# Postgres instead of in-memory SQLite. The suite normally runs on SQLite with
# dialect shims (conftest compiles JSONB/ARRAY/INET down, serialises list/dict
# params); that hides Postgres-specific behaviour the production DB exercises:
# pg_insert upsert paths, real JSONB columns, expression/partial indexes,
# transaction rollback semantics.
#
# Usage:  scripts/run_tests_postgres.sh [extra pytest args]
# Env:    PG_IMAGE (default postgres:16-alpine), PG_PORT (default 5433),
#         KEEP_PG=1 to keep the container around for re-runs.
set -euo pipefail

PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
PG_PORT="${PG_PORT:-5433}"
PG_CONTAINER="umbryx-test-pg"
PG_USER=umbryx
PG_PASS=umbryx
PG_DB=umbryx_test

cd "$(dirname "$0")/.."

cleanup() {
    if [ "${KEEP_PG:-0}" != "1" ] && [ "${_MANAGED_PG:-0}" = "1" ]; then
        docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# External URL (CI service container / docker service:postgres) wins —
# only bootstrap our own container when nothing was provided.
if [ -n "${SQLALCHEMY_TEST_URL:-}" ]; then
    echo "using provided SQLALCHEMY_TEST_URL"
    export APP_ENV=test
    exec python -m pytest -p no:cacheprovider -q --no-cov -W ignore::DeprecationWarning "$@"
fi
_MANAGED_PG=1

if ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$PG_CONTAINER" \
        -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASS" \
        -e POSTGRES_DB="$PG_DB" -p 127.0.0.1:"$PG_PORT":5432 \
        "$PG_IMAGE" >/dev/null
fi

echo "waiting for postgres on :$PG_PORT"
for i in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    [ "$i" = 60 ] && { echo "postgres did not become ready"; exit 1; }
done

export SQLALCHEMY_TEST_URL="postgresql+psycopg2://$PG_USER:$PG_PASS@127.0.0.1:$PG_PORT/$PG_DB"
export APP_ENV=test
echo "SQLALCHEMY_TEST_URL=$SQLALCHEMY_TEST_URL"

exec python -m pytest -p no:cacheprovider -q --no-cov -W ignore::DeprecationWarning "$@"
