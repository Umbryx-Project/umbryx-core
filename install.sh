#!/usr/bin/env bash
# Umbryx Platform Installer — interactive TUI wizard for deployment setup.
#
# Modes:
#   aio      — single-node "all-in-one" install (docker-compose.yml).
#
# Community Edition: the multi-node HA recipe is an Enterprise
# feature and is not carried in this tree (docs/modules/EDITIONS.md).
#
# --dry-run prints every mutating command instead of running it — use it
# to review exactly what a mode would do before committing to it on a
# real host.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Airgap bundle mode: the bundle ships pre-built images (umbryx-*) and
# compose files WITHOUT build: sections — there is no source tree here.
# Detected by the marker the bundle script writes; every build step is
# skipped and compose resolves image: tags from what install.sh loaded.
AIRGAP_BUNDLE=false
[ -f "$ROOT_DIR/.umbryx-airgap-bundle" ] && AIRGAP_BUNDLE=true
export UMBRYX_AIRGAP_BUNDLE="$AIRGAP_BUNDLE"

# In bundle mode the images ship beside this script: verify checksums and
# load them ONCE, before the menu — every deploy mode then just runs
# compose against the pre-loaded umbryx-* tags (no network, no builds).
load_bundle_images() {
  echo "--- Verifying image checksums ---"
  (cd images && sha256sum -c CHECKSUMS.sha256) || { echo "ERROR: checksum verification failed — do not trust this bundle."; exit 1; }
  echo "--- Loading images ---"
  local loaded
  for tarball in images/*.tar.gz; do
    [ -e "$tarball" ] || continue
    loaded="$(gunzip -c "$tarball" | docker load | sed -n 's/^Loaded image: //p' | tail -n1)"
    echo "  loaded: $loaded"
    # a bundle built from registry tags carries its registry name — retag
    # to the plain product tag compose expects (umbryx-backend:latest etc.)
    case "$(basename "$tarball")" in
      umbryx-backend.tar.gz)  [ -n "$loaded" ] && docker tag "$loaded" umbryx-backend:latest ;;
      umbryx-frontend.tar.gz) [ -n "$loaded" ] && docker tag "$loaded" umbryx-frontend:latest ;;
    esac
  done
}

DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h|--help)
      echo "Usage: $0 [--dry-run]"
      echo "Interactive installer. Run without arguments for the menu."
      echo "Set UMBRYX_INSTALL_NO_TUI=1 to force the plain-text fallback UI (no whiptail)."
      exit 0
      ;;
  esac
done

# ════════════════════════════════════════════════════════════════════
# UI layer — whiptail if available (installed on demand via apt when
# possible), otherwise a plain read-based fallback so the installer
# still works on a minimal host with nothing but bash.
# ════════════════════════════════════════════════════════════════════

WT_BIN=""

ui_detect() {
  if [ "${UMBRYX_INSTALL_NO_TUI:-}" = "1" ]; then
    WT_BIN=""
    return
  fi
  if command -v whiptail >/dev/null 2>&1; then
    WT_BIN="whiptail"
    return
  fi
  if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    apt-get install -y whiptail >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    sudo apt-get install -y whiptail >/dev/null 2>&1 || true
  fi
  if command -v whiptail >/dev/null 2>&1; then
    WT_BIN="whiptail"
  fi
}

# All ui_* functions echo their result to stdout (capture with $(...))
# except ui_msg/ui_yesno, which only affect exit status / are informational.

ui_msg() {
  local title="$1" text="$2"
  if [ -n "$WT_BIN" ]; then
    whiptail --title "$title" --msgbox "$text" 16 72
  else
    echo ""
    echo "== $title =="
    printf '%b\n' "$text"
    echo ""
    read -rp "Press Enter to continue..." _
  fi
}

ui_yesno() {
  local title="$1" text="$2"
  if [ -n "$WT_BIN" ]; then
    whiptail --title "$title" --yesno "$text" 14 72
    return $?
  else
    echo ""
    echo "== $title =="
    printf '%b\n' "$text"
    local ans
    read -rp "[y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]]
    return $?
  fi
}

ui_input() {
  local title="$1" text="$2" default="${3:-}"
  local result
  if [ -n "$WT_BIN" ]; then
    result=$(whiptail --title "$title" --inputbox "$text" 12 72 "$default" 3>&1 1>&2 2>&3) || { echo "__CANCELLED__"; return; }
  else
    echo "" >&2
    echo "== $title ==" >&2
    read -rp "$text [$default]: " result >&2
    result="${result:-$default}"
  fi
  echo "$result"
}

ui_password() {
  local title="$1" text="$2"
  local result
  if [ -n "$WT_BIN" ]; then
    result=$(whiptail --title "$title" --passwordbox "$text" 12 72 3>&1 1>&2 2>&3) || { echo "__CANCELLED__"; return; }
  else
    echo "" >&2
    echo "== $title ==" >&2
    read -rsp "$text: " result >&2
    echo "" >&2
  fi
  echo "$result"
}

# ui_menu title text tag1 item1 [tag2 item2 ...]
ui_menu() {
  local title="$1" text="$2"; shift 2
  local result
  if [ -n "$WT_BIN" ]; then
    result=$(whiptail --title "$title" --menu "$text" 20 78 10 "$@" 3>&1 1>&2 2>&3) || { echo "__CANCELLED__"; return; }
  else
    echo "" >&2
    echo "== $title ==" >&2
    printf '%b\n' "$text" >&2
    local -a tags=() labels=()
    while [ "$#" -gt 0 ]; do tags+=("$1"); labels+=("$2"); shift 2; done
    local i
    for i in "${!tags[@]}"; do
      printf "  %d) %s\n" "$((i + 1))" "${labels[$i]}" >&2
    done
    local choice
    read -rp "Choice [1-${#tags[@]}]: " choice >&2
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#tags[@]}" ]; then
      echo "__CANCELLED__"; return
    fi
    result="${tags[$((choice - 1))]}"
  fi
  echo "$result"
}

# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command '$1' not found in PATH." >&2
    exit 1
  fi
}

gen_hex() { openssl rand -hex "${1:-32}"; }

# Fernet key: urlsafe-base64 of exactly 32 random bytes. Prefer python3
# (matches .env.example's documented method exactly); fall back to pure
# openssl + tr when python3 isn't on the host yet (this installer is
# meant to run before the app's own Python environment exists).
gen_fernet() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null \
      || python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
  else
    openssl rand -base64 32 | tr '+/' '-_'
  fi
}

# Reject characters that would break shell/SQL string interpolation
# below (quotes, backticks, $, backslash, whitespace) instead of trying
# to escape them — simplest way to keep the SQL/shell we build safe.
validate_safe_str() {
  [[ "$1" =~ ^[A-Za-z0-9@%_+=:,.^~-]+$ ]]
}

prompt_safe_secret() {
  # prompt_safe_secret TITLE TEXT -> echoes a validated value, offering
  # a generated default so "just press Enter" is always the easy path.
  local title="$1" text="$2" suggestion value
  suggestion="$(gen_hex 16)"
  while true; do
    value=$(ui_input "$title" "$text
(leave as-is to use the generated value, or type your own)" "$suggestion")
    [ "$value" = "__CANCELLED__" ] && { echo "__CANCELLED__"; return; }
    if validate_safe_str "$value"; then
      echo "$value"; return
    fi
    ui_msg "Invalid value" "Only letters, digits, and @ % _ + = : , . ^ ~ - are allowed (no quotes, spaces, \$, or backticks) — this value gets embedded directly into shell and SQL commands."
  done
}

default_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -1
}

default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1
}

run_cmd() {
  # run_cmd DESCRIPTION -- actual command...
  local desc="$1"; shift
  echo ""
  echo ">>> $desc"
  echo "    \$ $*"
  if [ "$DRY_RUN" = true ]; then
    echo "    (dry-run: not executed)"
    return 0
  fi
  "$@"
}

wait_for_http() {
  local url="$1" tries="${2:-30}"
  local i
  for i in $(seq 1 "$tries"); do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

backup_if_exists() {
  local f="$1"
  if [ -f "$f" ]; then
    local bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$f" "$bak"
    echo "Backed up existing $f -> $bak"
  fi
}

# ════════════════════════════════════════════════════════════════════
# AIO — single-node install
# ════════════════════════════════════════════════════════════════════

# ── TLS on the platform nginx ─────────────────────────────────────────
# Writes docker-compose.https.yml (an override that re-mounts nginx.conf
# from nginx-ssl.conf and exposes 443) and nginx/certs/{cert,key}.pem.
# COMPOSE_FILE in .env makes every docker compose call pick it up —
# including the plain `docker compose up -d` below and the operator's
# own commands later.
setup_nginx_tls() {
  local mode="$1"

  mkdir -p nginx/certs

  if [ "$mode" = "self" ]; then
    echo "Generating self-signed certificate (nginx/certs/)..."
    run_cmd "openssl req -x509" openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout nginx/certs/key.pem -out nginx/certs/cert.pem \
      -subj "/CN=umbryx" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    chmod 600 nginx/certs/key.pem
  else
    local cert key
    cert=$(ui_input "Certificate" "Path to the certificate (PEM, full chain)" "")
    [ "$cert" = "__CANCELLED__" ] && return 1
    key=$(ui_input "Private key" "Path to the private key (PEM)" "")
    [ "$key" = "__CANCELLED__" ] && return 1
    [ -f "$cert" ] || { ui_msg "Not found" "Certificate file not found: $cert"; return 1; }
    [ -f "$key" ] || { ui_msg "Not found" "Key file not found: $key"; return 1; }
    run_cmd "Copying certificate" cp "$cert" nginx/certs/cert.pem
    run_cmd "Copying key" cp "$key" nginx/certs/key.pem
    chmod 600 nginx/certs/key.pem
  fi

  cat > docker-compose.https.yml <<'YMLEOF'
# Generated by install.sh — TLS on the platform nginx.
# Active while COMPOSE_FILE in .env includes this file; remove that line
# (and docker compose up -d) to return to plain HTTP.
services:
  nginx:
    ports:
      - "${PORT:-3000}:80"
      - "${HTTPS_PORT:-3443}:443"
    volumes:
      - type: bind
        source: ./nginx/nginx-ssl.conf
        target: /etc/nginx/nginx.conf
        read_only: true
      - type: bind
        source: ./nginx/certs
        target: /etc/nginx/certs
        read_only: true
YMLEOF

  compose_file="docker-compose.yml:docker-compose.https.yml"
  ui_msg "TLS configured" "nginx-ssl.conf mounted (HTTP redirects to HTTPS), certificate in nginx/certs/, port \${HTTPS_PORT:-3443} exposed.\n\nCOMPOSE_FILE is set in .env — every docker compose command picks the override up automatically."
}

install_aio() {
  require_cmd docker
  require_cmd openssl
  require_cmd curl

  ui_msg "All-in-one install" "This writes .env and brings up docker-compose.yml (db, redis, backend, frontend, nginx) on THIS host. Nothing else is touched."

  local db_user db_password db_name admin_user admin_password port app_env
  db_user=$(ui_input "Database" "Postgres username" "umbryx"); [ "$db_user" = "__CANCELLED__" ] && return
  db_name=$(ui_input "Database" "Postgres database name" "umbryx"); [ "$db_name" = "__CANCELLED__" ] && return
  db_password=$(prompt_safe_secret "Database" "Postgres password"); [ "$db_password" = "__CANCELLED__" ] && return

  admin_user=$(ui_input "Admin account" "Initial admin username" "admin"); [ "$admin_user" = "__CANCELLED__" ] && return
  admin_password=$(prompt_safe_secret "Admin account" "Initial admin password (change after first login)"); [ "$admin_password" = "__CANCELLED__" ] && return

  port=$(ui_input "Network" "Port to expose the platform on (nginx)" "3000"); [ "$port" = "__CANCELLED__" ] && return

  local env_choice
  env_choice=$(ui_menu "Environment" "Deployment environment" \
    production "Production (recommended — enforces ENCRYPTION_KEY, stricter defaults)" \
    dev "Development (relaxed checks, local testing only)")
  [ "$env_choice" = "__CANCELLED__" ] && return
  app_env="$env_choice"

  local cookie_secure="false"
  local https_mode="none"
  if [ "$app_env" = "production" ]; then
    local tls_choice
    tls_choice=$(ui_menu "HTTPS" "How is this instance reached?" \
      none   "Plain HTTP (testing only — login cookies will not require HTTPS)" \
      proxy  "HTTPS terminates on an external reverse proxy / load balancer" \
      self   "TLS right here on the platform nginx — generate a self-signed cert" \
      own    "TLS right here on the platform nginx — I have a certificate")
    [ "$tls_choice" = "__CANCELLED__" ] && tls_choice="none"
    case "$tls_choice" in
      proxy|self|own) cookie_secure="true"; https_mode="$tls_choice" ;;
    esac
  fi

  local https_port="3443"
  if [ "$https_mode" = "self" ] || [ "$https_mode" = "own" ]; then
    https_port=$(ui_input "HTTPS port" "Port to expose HTTPS on (nginx)" "3443")
    [ "$https_port" = "__CANCELLED__" ] && https_port="3443"
    setup_nginx_tls "$https_mode" || return
  fi

  echo "Generating secrets (JWT_SECRET, ENCRYPTION_KEY, WEBHOOK_HMAC_SECRET)..."
  local jwt_secret encryption_key webhook_secret
  jwt_secret=$(gen_hex 32)
  encryption_key=$(gen_fernet)
  webhook_secret=$(gen_hex 32)

  backup_if_exists .env
  cat > .env <<ENVEOF
# Generated by install.sh ($(date -u +%Y-%m-%dT%H:%M:%SZ))
DB_USER=${db_user}
DB_PASSWORD=${db_password}
DB_NAME=${db_name}

JWT_SECRET=${jwt_secret}
ENCRYPTION_KEY=${encryption_key}
REDIS_PASSWORD=

ADMIN_USERNAME=${admin_user}
ADMIN_PASSWORD=${admin_password}

APP_ENV=${app_env}
COOKIE_SECURE=${cookie_secure}
PORT=${port}
HTTPS_PORT=${https_port}
COMPOSE_FILE=${compose_file:-docker-compose.yml}

WEBHOOK_HMAC_SECRET=${webhook_secret}
ENVEOF
  echo ".env written."

  if ! ui_yesno "Ready to deploy" "Build images and start the platform now?\n\n  docker compose build\n  docker compose up -d\n\nThis can take a few minutes on first run."; then
    ui_msg "Stopped" ".env was written but nothing was started. Run 'docker compose up -d' yourself when ready."
    return
  fi

  if [ "$AIRGAP_BUNDLE" = true ]; then
    ui_msg "Airgap bundle" "Images are pre-loaded from the bundle — skipping the build, starting the platform."
    run_cmd "Starting platform" docker compose up -d --no-build
  else
    run_cmd "Building images" docker compose build
    run_cmd "Starting platform" docker compose up -d
  fi

  if [ "$DRY_RUN" = false ]; then
    echo ""
    echo "Waiting for the backend to become healthy..."
    # GET /api/health (DB check) — /api/auth/setup is POST-only and a GET
    # probe 405s forever, making every successful install look "unhealthy".
    if wait_for_http "http://localhost:${port}/api/health" 30; then
      ui_msg "Setup complete" "Platform is up.

URL:      http://localhost:${port}
Admin:    ${admin_user} / ${admin_password}

Change ADMIN_PASSWORD after first login. Secrets were written to .env (a backup of any previous .env was kept alongside it)."
    else
      ui_msg "Started, but not confirmed healthy yet" "The stack is up but didn't answer within the wait window. Check with: docker compose logs -f backend"
    fi
  else
    ui_msg "Dry run complete" "No containers were actually started. Re-run without --dry-run to deploy for real."
  fi
}


# ════════════════════════════════════════════════════════════════════
# Main menu
# ════════════════════════════════════════════════════════════════════

main() {
  ui_detect

  if [ "$AIRGAP_BUNDLE" = true ] && [ "$DRY_RUN" = false ]; then
    require_cmd docker
    load_bundle_images
  fi

  if [ "$DRY_RUN" = true ]; then
    echo "*** DRY RUN — no commands will actually be executed ***"
  fi

  while true; do
    # Community Edition: single-node installs. The multi-node HA recipe
    # is an Enterprise feature and is not carried in this tree at all.
    local -a entries=(aio "All-in-one — single node, everything on this host")
    entries+=(quit "Exit")

    local choice
    choice=$(ui_menu "Umbryx Platform Installer" "Select what to set up:" "${entries[@]}")

    case "$choice" in
      aio) install_aio ;;
      quit|__CANCELLED__|"") break ;;
    esac
  done
}

main "$@"
