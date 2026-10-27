#!/bin/bash
set -e
export PATH=$PATH:/usr/lib/postgresql/15/bin
PGDATA=/var/lib/postgresql/data
mkdir -p "$PGDATA" /var/run/postgresql /etc/mythic
chown -R postgres:postgres "$PGDATA" /var/run/postgresql
if [ ! -f "$PGDATA/PG_VERSION" ]; then
  su postgres -c "initdb -D '$PGDATA' -U postgres"
fi
su postgres -c "pg_ctl -D '$PGDATA' -o '-c listen_addresses=127.0.0.1' -l /tmp/pg.log start" || \
  su postgres -c "pg_ctl -D '$PGDATA' -o '-c listen_addresses=127.0.0.1' -l /tmp/pg.log restart"
psql -U postgres -c "SELECT 1 FROM pg_roles WHERE rolname='mythic' " | grep -q 1 || {
  psql -U postgres -c "CREATE USER mythic WITH PASSWORD 'mythic' SUPERUSER;"
  psql -U postgres -c "CREATE DATABASE mythic_db OWNER mythic;"
}
rabbitmq-plugins enable --offline rabbitmq_management >/dev/null 2>&1 || true
rabbitmq-server -detached
sleep 8
rabbitmqctl add_user mythic mythic 2>/dev/null || true
rabbitmqctl set_user_tags mythic administrator 2>/dev/null || true
rabbitmqctl add_vhost /mythic_vhost 2>/dev/null || true
rabbitmqctl set_permissions -p /mythic_vhost mythic ".*" ".*" ".*" 2>/dev/null || true
# TLS for nginx
[ -f /etc/mythic/tls.crt ] || openssl req -x509 -newkey rsa:2048 -keyout /etc/mythic/tls.key -out /etc/mythic/tls.crt -days 3650 -nodes -subj "/CN=mythic" 2>/dev/null
cp /etc/mythic/nginx.conf /etc/nginx/sites-enabled/mythic.conf && rm -f /etc/nginx/sites-enabled/default
nginx || nginx -s reload
# Hasura (graphql on 8080)
export HASURA_GRAPHQL_DATABASE_URL="postgres://mythic:mythic@127.0.0.1:5432/mythic_db"
export HASURA_GRAPHQL_ENABLE_CONSOLE=false
# Mythic actions.yaml references this env var in handler URLs
export MYTHIC_ACTIONS_URL_BASE="http://127.0.0.1:17443"
graphql-engine serve > /tmp/hasura.log 2>&1 &
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8080/healthz && break; sleep 2; done
hasura metadata apply --endpoint http://127.0.0.1:8080 --project /hasura-project --skip-update-check 2>&1 | tail -2 || echo "hasura metadata apply failed (continuing)"
export POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=5432 POSTGRES_USER=mythic POSTGRES_PASSWORD=mythic POSTGRES_DB=mythic_db
export RABBITMQ_HOST=127.0.0.1 RABBITMQ_PORT=5672 RABBITMQ_USER=mythic RABBITMQ_PASSWORD=mythic RABBITMQ_VHOST=/mythic_vhost
# Platform injects the generated password as ADMIN_PASSWORD — map it for Mythic
export MYTHIC_ADMIN_USER="${MYTHIC_ADMIN_USER:-admin}"
export MYTHIC_ADMIN_PASSWORD="${MYTHIC_ADMIN_PASSWORD:-$ADMIN_PASSWORD}"
echo "mythic-single: postgres+rabbitmq+hasura+nginx up, starting mythic_server"
/usr/src/app/mythic_server &
# Wait for mythic_server migrations to create tables, then apply hasura metadata
for i in $(seq 1 60); do
  curl -s -o /dev/null http://127.0.0.1:17443/health && break
  sleep 3
done
hasura metadata apply --endpoint http://127.0.0.1:8080 --project /hasura-project --skip-update-check 2>&1 | tail -2 || echo "hasura metadata apply failed (continuing)"
wait
