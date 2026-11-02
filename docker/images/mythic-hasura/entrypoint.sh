#!/bin/sh
set -e
# Wait for the mythic server (its migrations create the tables the metadata
# describes) before applying metadata.
until curl -sf -m 3 -o /dev/null "${MYTHIC_SERVER_URL:-http://mythic-server:17443}/health"; do
  echo "waiting for mythic-server"; sleep 5
done
graphql-engine serve > /tmp/hasura.log 2>&1 &
for i in $(seq 1 30); do
  curl -sf -m 2 -o /dev/null http://127.0.0.1:8080/healthz && break
  sleep 2
done
hasura-cli metadata apply --endpoint http://127.0.0.1:8080 --project /hasura-project --skip-update-check 2>&1 | tail -2 \
  || echo "WARN: metadata apply failed"
exec tail -f /tmp/hasura.log
