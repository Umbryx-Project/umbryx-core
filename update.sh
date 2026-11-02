#!/usr/bin/env bash
# Umbryx Platform Update — safe in-place update of an EXISTING deployment.
#
# Complements install.sh (fresh installs): this script never touches .env,
# data/ or volumes — it only replaces the code/images and recreates the
# containers, with backups and a rollback path.
#
#   ./update.sh             # update: backup → new images/containers → health check
#   ./update.sh --rollback  # roll back to the images from before the last update
#   ./update.sh --no-backup # skip the .env copy + DB dump
#   ./update.sh --no-wait   # don't wait for backend health at the end
#
# Works in both deployment shapes:
#   * source tree  — docker compose build, then up -d
#   * airgap bundle (detected by .umbryx-airgap-bundle) — verify checksums,
#     docker load the bundled images, then up -d --no-build
#
# Rollback notes: --rollback restores the previous images and restarts, but
# does NOT revert database migrations. If the new version migrated the DB
# and you need to go back, also restore the dump this script saved in
# backups/ (on a stopped stack) — see the hint it prints.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

DO_BACKUP=true
WAIT_HEALTH=true
MODE="update"
for arg in "$@"; do
  case "$arg" in
    --no-backup) DO_BACKUP=false ;;
    --no-wait)   WAIT_HEALTH=false ;;
    --rollback)  MODE="rollback" ;;
    -h|--help)   grep -E '^#   \./update.sh' "$0" | sed 's/^# *//'; exit 0 ;;
    *) echo "ERROR: unknown option: $arg (see --help)" >&2; exit 1 ;;
  esac
done

TS="$(date +%Y%m%d-%H%M%S)"
AIRGAP=false
[ -f "$ROOT_DIR/.umbryx-airgap-bundle" ] && AIRGAP=true

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "docker not found in PATH"
docker compose version >/dev/null 2>&1 || fail "docker compose plugin not found"
[ -f docker-compose.yml ] || fail "docker-compose.yml not found in $ROOT_DIR — run this script from the deployment directory"
[ -f .env ]               || fail ".env not found — this doesn't look like a deployed instance. Use ./install.sh for a fresh install."

PORT="$(grep -E '^PORT=' .env | tail -1 | cut -d= -f2-)"
PORT="${PORT:-3000}"
DB_USER="$(grep -E '^DB_USER=' .env | tail -1 | cut -d= -f2-)"
DB_NAME="$(grep -E '^DB_NAME=' .env | tail -1 | cut -d= -f2-)"
DB_USER="${DB_USER:-umbryx}"
DB_NAME="${DB_NAME:-umbryx}"

# ── Rollback mode ────────────────────────────────────────────────────────────
if [ "$MODE" = "rollback" ]; then
  say "Rollback: restoring images from before the last update"
  for img in backend frontend; do
    if docker image inspect "umbryx-$img:rollback" >/dev/null 2>&1; then
      docker tag "umbryx-$img:rollback" "umbryx-$img:latest"
      echo "  umbryx-$img:rollback → umbryx-$img:latest"
    else
      echo "  no umbryx-$img:rollback tag found — keeping current image"
    fi
  done
  docker compose up -d
  # nginx caches upstream container IPs at startup; after recreating
  # backend/frontend a still-running nginx 502s (111: Connection
  # refused) until restarted. The resolver-valid= fix self-heals in
  # ≤10s; this restart makes it instant.
  docker compose restart nginx
  echo ""
  echo "NOTE: rollback does NOT revert database migrations. If the updated"
  echo "version migrated the DB and you need a true revert, restore the dump"
  echo "from backups/ (stack stopped: docker compose down, remove the pgdata"
  echo "volume, docker compose up -d db, restore the dump, docker compose up -d)."
  exit 0
fi

# ── Backups ──────────────────────────────────────────────────────────────────
if [ "$DO_BACKUP" = true ]; then
  say "Backups"
  mkdir -p backups
  cp .env "backups/env-$TS.bak"
  echo "  .env → backups/env-$TS.bak"
  if docker ps --format '{{.Names}}' | grep -q '^umbryx_db$'; then
    if docker exec umbryx_db pg_dump -U "$DB_USER" "$DB_NAME" > "backups/db-$TS.sql" 2>/dev/null; then
      echo "  database → backups/db-$TS.sql ($(du -h "backups/db-$TS.sql" | cut -f1))"
    else
      rm -f "backups/db-$TS.sql"
      echo "  WARNING: pg_dump failed — continuing without a DB backup"
    fi
  else
    echo "  WARNING: umbryx_db is not running — skipped the DB dump"
  fi
else
  say "Backups skipped (--no-backup)"
fi

# ── Keep the current images as the rollback point ───────────────────────────
say "Tagging current images as the rollback point"
for img in backend frontend; do
  if docker image inspect "umbryx-$img:latest" >/dev/null 2>&1; then
    docker tag "umbryx-$img:latest" "umbryx-$img:rollback"
    echo "  umbryx-$img:latest → :rollback"
  fi
done

# ── New code/images ──────────────────────────────────────────────────────────
if [ "$AIRGAP" = true ]; then
  say "Airgap bundle: verifying checksums and loading images"
  [ -d images ] && [ -f images/CHECKSUMS.sha256 ] || fail "bundle marker present but images/CHECKSUMS.sha256 not found"
  (cd images && sha256sum -c CHECKSUMS.sha256 >/dev/null) || fail "checksum verification failed — do not trust this bundle"
  echo "  checksums OK"
  for tarball in images/*.tar.gz; do
    [ -e "$tarball" ] || continue
    loaded="$(gunzip -c "$tarball" | docker load | sed -n 's/^Loaded image: //p' | tail -n1)"
    echo "  loaded: $loaded"
    case "$(basename "$tarball")" in
      umbryx-backend.tar.gz)  [ -n "$loaded" ] && docker tag "$loaded" umbryx-backend:latest ;;
      umbryx-frontend.tar.gz) [ -n "$loaded" ] && docker tag "$loaded" umbryx-frontend:latest ;;
    esac
  done
else
  say "Building images from the source tree"
  docker compose build --pull
fi

# ── Recreate containers ──────────────────────────────────────────────────────
say "Recreating containers (volumes and .env are not touched)"
if [ "$AIRGAP" = true ]; then
  docker compose up -d --no-build
else
  docker compose up -d
  # nginx caches upstream container IPs at startup; after recreating
  # backend/frontend a still-running nginx 502s (111: Connection
  # refused) until restarted. The resolver-valid= fix self-heals in
  # ≤10s; this restart makes it instant.
  docker compose restart nginx
fi

# ── Health check ─────────────────────────────────────────────────────────────
if [ "$WAIT_HEALTH" = true ]; then
  say "Waiting for the backend to become healthy (migrations may take a while)"
  ok=false
  for _ in $(seq 1 60); do
    if curl -sf "http://localhost:${PORT}/api/health" >/dev/null 2>&1; then ok=true; break; fi
    sleep 5
  done
  if [ "$ok" = true ]; then
    echo "  healthy: http://localhost:${PORT}/api/health"
  else
    echo "  backend did not answer within 5 minutes. Logs:"
    docker compose logs --tail 40 backend || true
    fail "update not confirmed healthy — see the logs above; ./update.sh --rollback can restore the previous images"
  fi
fi

say "Update complete"
docker compose ps
echo ""
echo "Rollback (images only, DB migrations are NOT reverted):"
echo "  ./update.sh --rollback"
