# Editions

Umbryx ships as two builds from one source tree.

**Community Edition** is the public one. It is the whole platform except the
code that deploys and manages attack infrastructure for you. Everything an
operator does with their *own* machines stays here, and so does every piece of
the audit trail.

**Enterprise Edition** adds the infrastructure side: the service catalog, the
stack builder, cloud providers, DNS and TLS automation, and workstation
provisioning. It needs a signed license and is distributed from a private
registry.

| | Community Edition | Enterprise Edition |
|---|---|---|
| Image | `umbryx:X.Y.Z` | `umbryx-ee:X.Y.Z` |
| Registry | public | private, access with the license |
| Source | public mirror, no `ee/` | private repository |
| License key | not needed | signed Ed25519 token |
| Legal license | BSL 1.1 + production use grant | BSL 1.1, production under contract |
| Multi-node HA recipe | not published | `docker-compose.ha.yml` + installer modes |

## What Community Edition can do

Everything the screenshots in [README.md](README.md) show, except where noted
below: projects, scope and rules of engagement, hosts, credentials, findings,
notes, loot, the knowledge base, the network map and attack graph, attack
paths, objectives, scans and jobs, playbooks and automations, the report
builder, the timeline, the checklist, full RBAC, SSO, and the complete audit
trail.

It also keeps everything to do with the operator's own machines: attacker-SSH
targets without limit, registering a machine by SSH, granting and revoking
SSH access to it, and the shell action log for it, under
**Workstations → pool & access**. The DevOps log — what the platform did, and
when — is in **Admin → DevOps Log** in both editions. Those are deliberately not
behind the paywall — revoking someone's access is a safety feature, and an
audit trail with holes in it is worth nothing.

## What only Enterprise Edition can do

One thing, with several faces: **Umbryx deploying infrastructure for you.**

- **Infrastructure catalog and builder** — C2 and redirector stacks, phishing
  kits and pivot chains as templates you deploy and tear down as a unit.
- **Cloud providers** — Hetzner, Proxmox, AWS, and the rest, driven from the
  platform.
- **DNS and TLS automation** — records and certificates created and revoked
  with the stack that needs them.
- **Workstation provisioning** — requesting a machine from a template, rather
  than registering one you already have.

In Community Edition the whole Infrastructure page is absent — not empty, not
greyed out, simply not in the navigation. There are no disabled buttons and no
upsell dialogs: a screen that does nothing is not shown.
That is different from the tier badges you may see in either edition, which
are about the license tier rather than the build.

### Multi-node high availability

This one sits differently from the list above: it is a packaging decision,
not a capability the code withholds. Every edition reads `DB_HOST`,
`DB_PORT`, `DB_SSLMODE` and the `REDIS_SENTINEL_*` variables, so a Community
install can be pointed at a Postgres cluster and a Sentinel quorum you built
yourself, and it will use them. What Enterprise publishes is the recipe —
`docker-compose.ha.yml` (pg_auto_failover, HAProxy, keepalived, Redis
Sentinel), the installer's HA modes, and the bootstrap sequence with its
one-shot registration handshake documented.

## The database schema is the same in both

Models and migrations live in the core for Enterprise-only tables too. A
Community instance creates every table, including the ones it never writes to.
This is what makes the upgrade an image swap:

```bash
docker compose pull            # with umbryx-ee:X.Y.Z configured
docker compose up -d
```

No export, no import, no migration. Downgrading works the same way; the
Enterprise rows simply stop being read.

## License

Both editions are under the Business Source License 1.1, in [LICENSE](LICENSE).

The Additional Use Grant there permits **production use of Community
Edition** — inside a commercial organization, and for paid security
assessments you carry out for your clients. What it does not permit is
offering Umbryx to third parties as a hosted or managed service, and it does
not cover production use of the Enterprise source, which is a commercial
agreement with the licensor.

On 2030-05-30 the license converts to Apache 2.0.

## Regenerating the screenshots

Both sets come from a throwaway stand filled with synthetic data, never from a
real instance:

```bash
scripts/demo-stand.sh up                                     # EE stand on :8899
scripts/capture-screenshots.py --edition ee --out docs/screenshots/ee

scripts/build-ce.sh ../umbryx-ce                             # build the CE tree
cd ../umbryx-ce && DEMO_PROJECT=umbryx-ce-demo DEMO_PORT=8898 \
    DEMO_SUBNET=10.202.0.0/24 scripts/demo-stand.sh up       # CE stand on :8898
scripts/capture-screenshots.py --edition ce --url http://localhost:8898 \
    --out docs/screenshots/ce
```

The seeded data is reproducible — pinned ids and timestamps — so re-capturing
an unchanged UI produces unchanged frames.
