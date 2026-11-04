#!/usr/bin/env bash
#
# Produce a Umbryx Community Edition source tree from this repository.
#
# The split is build-time (docs/modules/EDITIONS.md): one private source
# tree, two artifacts. This script makes the public one by copying the tree
# and removing the Enterprise package from the copy.
#
#   scripts/build-ce.sh [DEST] [--allow-dirty] [--no-git]
#
# DEST defaults to ../umbryx-ce. The destination's contents are replaced,
# and the result is a standalone git repository of its own: the Community
# tree is meant to be pushed to its own public remote, separate from this
# private tree's history.
#
# Re-running it on a destination built earlier KEEPS that destination's
# .git — its history and its remotes — and commits the new export on top.
# So the publishing loop is: build here, push there. Nothing in this
# script talks to a remote; pushing stays the owner's step.
#
# It never modifies the working tree it reads from, and it refuses to run
# on a tree with uncommitted changes unless --allow-dirty is given — the
# public artifact should correspond to a commit someone can point at.
#
# What it removes:
#   backend/app/ee/         the Enterprise backend (deployment)
#   frontend/src/ee/        the Enterprise frontend (deployment UI)
#   docs/modules/           internal design docs, including this split's own
#   graphify-out/           21MB of a code-analysis tool's AST cache, tracked
#                           in the private tree by accident; nothing builds
#                           from it and a published repository should not
#                           carry one contributor's tool state
#   docs/screenshots/ee/    the Enterprise screenshot set — it shows screens
#                           this build does not have
#   docker-compose.ha.yml   the multi-node HA recipe, with docker/ha/ and the
#   docker/ha/              two .env.ha node examples. Enterprise publishes
#   .env.ha.node-*.example  the recipe; nothing in the code enforces it, and
#                           install.sh hides its HA modes when the compose
#                           file is absent (has_ha)
#   .git/                   history of the private tree
#
# What it rewrites:
#   README.md               screenshot embeds repointed at the Community set,
#                           and the frames fenced <!-- ee-only --> dropped.
#                           One README is maintained, not two: a second copy
#                           drifts the moment either is edited.
#
# What it deliberately keeps:
#   models and Alembic migrations, including for Enterprise-only tables —
#     the two editions share one schema so that upgrading Community to
#     Enterprise needs no data migration at all;
#   the whole test suite — Enterprise tests skip themselves in a Community
#     build (the `ee` marker and pytest.importorskip);
#   the licensing code — a Community install reports its own edition and
#     can accept a license, which is what makes the upgrade a swap of the
#     image rather than a migration;
#   LICENSE — BSL 1.1 whose Additional Use Grant permits production use of
#     exactly this artifact (the tree with the Enterprise source removed),
#     which is what makes the Community Edition usable for real work;
#   EDITIONS.md — the public explanation of what this build is and is not.
#     It lives at the root rather than in docs/modules/ precisely so that it
#     survives this script; before it existed the Community repository
#     described features it did not ship and said nothing about why.

set -euo pipefail

DEST=""
ALLOW_DIRTY=0
INIT_GIT=1
for arg in "$@"; do
  case "$arg" in
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --no-git) INIT_GIT=0 ;;
    *) DEST="$arg" ;;
  esac
done

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${DEST:-$(dirname "$SRC")/umbryx-ce}"

cd "$SRC"

if [ "$ALLOW_DIRTY" -eq 0 ]; then
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "error: working tree has uncommitted changes." >&2
    echo "       A published Community artifact should match a commit." >&2
    echo "       Commit them, or pass --allow-dirty to build anyway." >&2
    exit 1
  fi
fi

REV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

echo "Umbryx Community Edition build"
echo "  source: $SRC ($REV)"
echo "  dest:   $DEST"

if [ -e "$DEST" ]; then
  # Refuse to touch anything that is not a previous output of this script,
  # so a mistyped destination cannot delete an unrelated directory.
  if [ ! -f "$DEST/.umbryx-ce" ]; then
    echo "error: $DEST exists and was not produced by this script." >&2
    echo "       Remove it yourself if that is what you intend." >&2
    exit 1
  fi
  # Clear the export but keep .git: the destination is a published
  # repository, and its history and remotes must survive a rebuild.
  find "$DEST" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
fi

mkdir -p "$DEST"

# Copy with git, so .gitignore is honoured and no node_modules, venv,
# __pycache__ or build output comes along.
git archive --format=tar HEAD | tar -x -C "$DEST"

cd "$DEST"

rm -rf backend/app/ee
rm -rf frontend/src/ee
rm -rf docs/modules
rm -rf graphify-out
rm -rf docs/screenshots/ee
rm -f docker-compose.ha.yml .env.ha.node-a.example .env.ha.node-b.example
rm -rf docker/ha

# The README is kept as one file in the private tree rather than maintained
# twice: a second copy drifts the moment either is edited. Here it is adapted
# to what this build actually is — the screenshot embeds point at the
# Community set, and the frames of screens that do not exist in this edition
# are dropped. Those are fenced with <!-- ee-only --> in README.md precisely
# so this can remove them without guessing at headings.
python3 - <<'PYEOF'
import io, re


def sub(path, old, new, count=1):
    """Replace anchored text, or stop the build.

    A rewrite that silently matches nothing is the failure mode that matters
    here: the export would still be produced, and it would describe an HA
    setup it does not ship.
    """
    s = io.open(path, encoding="utf-8").read()
    n = s.count(old)
    if n != count:
        head = old.strip().splitlines()[0][:70]
        raise SystemExit(
            "error: build-ce.sh: %s: expected %d occurrence(s) of %r, found %d\n"
            "       — the private tree moved and this rewrite is stale."
            % (path, count, head, n)
        )
    io.open(path, "w", encoding="utf-8").write(s.replace(old, new))


p = "README.md"
s = io.open(p, encoding="utf-8").read()
s = re.sub(r"<!-- ee-only -->.*?<!-- /ee-only -->\n?", "", s, flags=re.S)
s = s.replace("docs/screenshots/ee/", "docs/screenshots/ce/")
s = s.replace(
    "The screenshots below\nare from Enterprise Edition; sections that only exist there say so.",
    "This is the Community Edition tree, and the screenshots below are from it;\nsections describing Enterprise Edition say so.",
)
io.open(p, "w", encoding="utf-8").write(s)

# The HA recipe is not in this export, so neither are the paths leading to
# it. Both of the links below were already broken in the published tree,
# since docs/modules/ is removed above — fixing them is overdue regardless.
sub(
    "README.md",
    "- **Multi-node HA** — walks through the exact sequence in "
    "[docs/modules/HA_DEPLOYMENT.md](docs/modules/HA_DEPLOYMENT.md) "
    "(pg_auto_failover monitor, DB role creation, HAProxy/keepalived VIP, Redis Sentinel) "
    "on the seed node, joining a second node, and pointing the app layer at the cluster VIP. "
    "pg_auto_failover registration is a one-shot handshake \u2014 read the confirmation prompts "
    "before proceeding on a live cluster.\n",
    "",
)
sub(
    "README.md",
    "writes `.env`/`.env.ha`, and brings the stack up for you \u2014 no manual editing. "
    "Covers both deployment modes:",
    "writes `.env`, and brings the stack up for you \u2014 no manual editing:",
)
sub(
    "README.md",
    """This `docker-compose.yml` is single-node: one `db`, one `redis`, done. For
automatic failover across 2+ hosts (Postgres via pg_auto_failover, Redis
via Sentinel, a floating VIP, no manual intervention on a node loss), see
**`docker-compose.ha.yml`** and **[docs/modules/HA_DEPLOYMENT.md](docs/modules/HA_DEPLOYMENT.md)**
\u2014 a separate compose file for the infrastructure layer, run alongside
this one. Live-tested: killed the primary Postgres node under real
traffic, zero hung requests, ~41s to full automatic recovery, all data
(including encrypted credential secrets) intact on either node afterward.""",
    """This `docker-compose.yml` is single-node: one `db`, one `redis`, done. The
packaged multi-node recipe \u2014 Postgres via pg_auto_failover, Redis via
Sentinel, a floating VIP, automatic failover on a node loss \u2014 is part of
Enterprise Edition; see [EDITIONS.md](EDITIONS.md).

This edition does not stop you running the database and Redis in HA
yourself. `DB_HOST` / `DB_PORT` / `DB_SSLMODE` point the app at any
external Postgres, a cluster VIP included, and `REDIS_SENTINEL_HOSTS`
points Redis access at a Sentinel quorum \u2014 both are read by this build.
What Enterprise adds is the compose file, the installer path and the
documented bootstrap sequence for it.""",
)
sub(
    "README.md",
    " \u2014 e.g. a multi-node HA cluster's VIP. See \"Multi-node HA\" below. |",
    " \u2014 e.g. an external Postgres cluster's VIP. See \"Multi-node HA\" below. |",
)
sub(
    "CONTRIBUTING.md",
    "All feature work must follow the branch model from "
    "[docs/modules/WORKFLOW_RULES.md](docs/modules/WORKFLOW_RULES.md).",
    "All feature work follows the branch model below.",
)
PYEOF

# Provenance, and the marker this script checks before it clears a
# destination. It carries no build timestamp on purpose: the file is
# committed to the Community repository, and a timestamp would make every
# re-export differ from the last one even when the source revision has
# not moved. When the export happened is already the commit's own date.
cat > .umbryx-ce <<EOF
Umbryx Community Edition
built from $REV
EOF

# Fail loudly rather than publish a tree that still carries Enterprise code.
leaks=0
for path in backend/app/ee frontend/src/ee docs/screenshots/ee \
            docker-compose.ha.yml docker/ha .env.ha.node-a.example \
            .env.ha.node-b.example; do
  if [ -e "$path" ]; then
    echo "error: $path survived removal" >&2
    leaks=1
  fi
done
# Match import statements, not mentions: core documents the seam in its
# comments on purpose, and the stub's own docstring names the directory it
# stands in for. What must not survive is anything that would actually
# resolve app.ee or src/ee at import time.
backend_leaks="$(grep -rnE "^[[:space:]]*(from|import)[[:space:]]+(app\.ee|\.+ee)([[:space:].]|$)" \
  --include="*.py" backend/app 2>/dev/null || true)"
if [ -n "$backend_leaks" ]; then
  echo "error: backend code still imports the Enterprise package:" >&2
  echo "$backend_leaks" >&2
  leaks=1
fi
frontend_leaks="$(grep -rnE "(from|import)[[:space:]]*['\"][^'\"]*(\.\./)*ee/" \
  --include="*.jsx" --include="*.js" frontend/src 2>/dev/null | grep -v "/ee-stub/" || true)"
if [ -n "$frontend_leaks" ]; then
  echo "error: frontend code still imports from src/ee by path:" >&2
  echo "$frontend_leaks" >&2
  leaks=1
fi
[ "$leaks" -eq 0 ] || exit 1

if [ "$INIT_GIT" -eq 1 ]; then
  if [ ! -d .git ]; then
    git init -q -b main
    echo "  initialised a new git repository (branch main)"
  fi
  git add -A
  if git diff --cached --quiet; then
    echo "  no change since the last export — nothing committed"
  else
    git commit -q -m "Umbryx Community Edition: export from $REV"
    echo "  committed: $(git rev-parse --short HEAD) on $(git branch --show-current)"
  fi
  remote="$(git remote 2>/dev/null | head -1)"
  if [ -n "$remote" ]; then
    echo "  remote '$remote' is configured — push it yourself when ready"
  else
    echo "  no remote configured yet: git -C $DEST remote add origin <url>"
  fi
fi

echo
echo "Community tree ready."
echo "  backend:  python -c 'from app.main import app'  -> edition 'ce'"
echo "  frontend: npm run build                         -> @ee resolves to src/ee-stub"
echo "  tests:    python -m pytest                      -> Enterprise tests skip"
