#!/usr/bin/env bash
# Builds a self-contained installation bundle for deploying the core Umbryx
# platform (backend/frontend/nginx + postgres/redis) into an isolated
# network segment with no internet access. Run this on a machine that DOES
# have internet/registry access and a local docker build of the project;
# ship the resulting tar.gz to the target host and run install.sh there.
#
# Out of scope on purpose: the C2/redirector infrastructure images under
# docker/images/ (adaptix, sliver, evilginx2, iodine, covenant, mythic).
# Those are deployed by the platform's own infra engine onto engagement
# infrastructure at operation time, not part of standing up the platform
# itself — bundle them separately with docker/build-images.sh if a given
# engagement's isolated segment also needs to run C2 teamservers locally.
#
# SKIP_BUILD=1 skips `docker compose build` and expects BACKEND_IMAGE/
# FRONTEND_IMAGE (with IMAGE_TAG) to already exist locally — set by the
# build-airgap-bundle CI job, which pulls the images the build stage
# already pushed instead of rebuilding them a second time.
#
# VERSION overrides the default timestamp-based version string — the CI
# job pins it to $CI_COMMIT_SHORT_SHA so the resulting filename is
# deterministic and matches the package version it uploads to.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${VERSION:-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="dist/umbryx-airgap-${VERSION}"
BACKEND_IMAGE="${BACKEND_IMAGE:-umbryx-backend}:${IMAGE_TAG:-latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-umbryx-frontend}:${IMAGE_TAG:-latest}"

echo "=== Building Umbryx airgap bundle (${VERSION}) ==="

if [ "${SKIP_BUILD:-}" = "1" ]; then
    echo ""
    echo "--- Skipping build (SKIP_BUILD=1) — expecting ${BACKEND_IMAGE} / ${FRONTEND_IMAGE} to already exist locally (e.g. docker pull'd from a registry in CI) ---"
    docker image inspect "$BACKEND_IMAGE" >/dev/null || { echo "ERROR: $BACKEND_IMAGE not found locally — pull or build it first."; exit 1; }
    docker image inspect "$FRONTEND_IMAGE" >/dev/null || { echo "ERROR: $FRONTEND_IMAGE not found locally — pull or build it first."; exit 1; }
else
    echo ""
    echo "--- Building backend/frontend images ---"
    docker compose build backend frontend
fi

echo ""
echo "--- Ensuring base images are pulled ---"
docker pull postgres:16-alpine
docker pull redis:7.2-alpine
docker pull nginx:alpine

# every image ships under its product name (umbryx-<role>): on the
# target host `docker images` shows what the appliance installed
docker tag postgres:16-alpine umbryx-postgres:16-alpine
docker tag redis:7.2-alpine umbryx-redis:7.2-alpine
docker tag nginx:alpine umbryx-nginx:alpine
docker tag "$BACKEND_IMAGE" umbryx-backend:"${IMAGE_TAG:-latest}"
docker tag "$FRONTEND_IMAGE" umbryx-frontend:"${IMAGE_TAG:-latest}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/images"

echo ""
echo "--- Saving images (this takes a while) ---"
save() {
    local image="$1" name="$2"
    echo "Saving ${image} -> images/${name}.tar.gz"
    docker save "$image" | gzip -1 > "$OUT_DIR/images/${name}.tar.gz"
}
save "umbryx-backend:${IMAGE_TAG:-latest}" "umbryx-backend"
save "umbryx-frontend:${IMAGE_TAG:-latest}" "umbryx-frontend"
save "umbryx-postgres:16-alpine" "umbryx-postgres"
save "umbryx-redis:7.2-alpine" "umbryx-redis"
save "umbryx-nginx:alpine" "umbryx-nginx"

echo ""
echo "--- Writing image checksums ---"
(cd "$OUT_DIR/images" && sha256sum ./*.tar.gz > CHECKSUMS.sha256)

echo ""
echo "--- Copying compose/config/modules ---"
# Strip the `build:` directives — the bundle ships no backend/frontend
# source, only pre-built images loaded from images/*.tar.gz. Leaving
# `build:` in place is what causes `docker compose up` to try to build
# from a nonexistent ./backend / ./frontend context on a bare install
# host instead of just using the loaded image, even when the loaded image
# already satisfies the `image:` tag — this is the actual fix for
# "images don't import cleanly", not just relying on operators
# remembering to pass --no-build.
sed -E -e '/^[[:space:]]*build:[[:space:]]*\.\/(backend|frontend)[[:space:]]*$/d' \
       -e 's#image: postgres:16-alpine#image: umbryx-postgres:16-alpine#' \
       -e 's#image: redis:7.2-alpine#image: umbryx-redis:7.2-alpine#' \
       -e 's#image: nginx:alpine#image: umbryx-nginx:alpine#' \
    docker-compose.yml > "$OUT_DIR/docker-compose.yml"
cp .env.example "$OUT_DIR/.env.example"
mkdir -p "$OUT_DIR/nginx"
cp nginx/nginx.conf "$OUT_DIR/nginx/nginx.conf"
# nginx.conf unconditionally does `include /etc/nginx/access-control.conf`
# (empty by default, real content only for multi-node HA) — bind-mounted in
# docker-compose.yml from ./nginx/access-control.conf. Without this file
# present on the target host, Docker silently creates an empty *directory*
# at that bind-mount source (its usual behavior for a missing host path),
# and nginx then fails to start: `pread() ".../access-control.conf" failed
# (21: Is a directory)` — reproduced end-to-end on a real bundle install.
cp nginx/access-control.conf "$OUT_DIR/nginx/access-control.conf"
cp -r modules "$OUT_DIR/modules"
# Empty runtime data dir, shipped so the bind mount in docker-compose.yml
# (${DATA_DIR:-./data}:/data) resolves to something that already exists
# with the right layout — operators don't need to mkdir it by hand before
# first start. Intentionally contains no data, just the directory itself
# (tar preserves empty directories).
mkdir -p "$OUT_DIR/data"
# ONE installer — the interactive wizard (aio in Community). It detects
# the bundle via the marker: verifies checksums, loads the umbryx-*
# images, never builds, never touches the network.
cp install.sh "$OUT_DIR/install.sh"
chmod +x "$OUT_DIR/install.sh"
# Update path for already-deployed bundles: same backups/rollback/health
# flow as the online update.sh, against the pre-loaded images.
cp update.sh "$OUT_DIR/update.sh"
chmod +x "$OUT_DIR/update.sh"
touch "$OUT_DIR/.umbryx-airgap-bundle"

cat > "$OUT_DIR/README.md" <<'EOF'
# Umbryx — offline install bundle

Contents:
- `images/umbryx-*.tar.gz` + `images/CHECKSUMS.sha256` — umbryx-backend, umbryx-frontend, umbryx-postgres, umbryx-redis, umbryx-nginx (docker save output)
- `docker-compose.yml` — same as the platform ships, minus the `build:` directives (no source tree in this bundle, so `docker compose up` always resolves the `image:` tags from the images loaded above, whether or not you remember `--no-build`)
- `nginx/nginx.conf`, `nginx/access-control.conf`, `.env.example`, `modules/` — same files the platform ships with
- `data/` — empty runtime data directory (matches the `${DATA_DIR:-./data}:/data` bind mount), shipped so there's nothing to `mkdir` by hand before first start
- `install.sh` — the interactive installer: verifies image checksums, loads the images, asks the deployment questions, writes `.env` (fresh secrets) and starts the stack. No source checkout, no network access, no builds

## Install

On the target host, with docker + the compose plugin already installed:

```
sha256sum -c umbryx-airgap-<version>.tar.gz.sha256   # verify transfer integrity first

# Fresh install: unpack into its own directory (the tarball has a
# top-level umbryx-airgap-<version>/ folder inside)
tar xzf umbryx-airgap-<version>.tar.gz
cd umbryx-airgap-<version>
./install.sh   # verifies images/CHECKSUMS.sha256 before loading anything

# Updating an EXISTING deployment: unpack over the current directory
# with --strip-components=1 (drops the top-level folder; .env and data/
# are not part of the bundle and stay untouched), then run update.sh
cd <deployment-dir>
tar xzf umbryx-airgap-<new-version>.tar.gz -C . --strip-components=1
./update.sh
```

## Notes

- `install.sh` generates fresh secrets (`JWT_SECRET`, `ENCRYPTION_KEY`, DB/Redis passwords, admin password) into `.env` on first run. Back up `.env` — losing `ENCRYPTION_KEY`/`JWT_SECRET` makes existing encrypted data unreadable and invalidates all sessions.
- `DNS_SERVER_1`/`DNS_SERVER_2` in `.env` default to public resolvers, only used by the backend container for scan-target DNS resolution — point them at an internal resolver if the isolated segment has one, otherwise leave unset.
- To update later: rebuild a new bundle with `scripts/build-airgap-bundle.sh`, ship it, `docker compose down` is NOT needed — just re-run `install.sh` (it reuses the existing `.env` and does a `docker compose up -d --no-build` with the freshly loaded images).
- Migrations run automatically on backend startup (`alembic upgrade head`), no manual step needed.
EOF

echo ""
echo "--- Packing archive ---"
tar czf "dist/umbryx-airgap-${VERSION}.tar.gz" -C dist "umbryx-airgap-${VERSION}"
rm -rf "$OUT_DIR"

echo ""
echo "--- Writing bundle checksum ---"
(cd dist && sha256sum "umbryx-airgap-${VERSION}.tar.gz" > "umbryx-airgap-${VERSION}.tar.gz.sha256")

echo ""
echo "=== Done ==="
ls -lh "dist/umbryx-airgap-${VERSION}.tar.gz" "dist/umbryx-airgap-${VERSION}.tar.gz.sha256"
echo "Verify after transferring to the isolated host with:"
echo "  sha256sum -c umbryx-airgap-${VERSION}.tar.gz.sha256"
