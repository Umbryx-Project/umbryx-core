# Infrastructure Architecture — Stack, Deployment, and Auto-Integration

## 1. Stack vs Deployment

### Decision: There is only ONE entity — `InfraStack`.

"Deployment" does not exist as a separate model, table, or entity. It is:

1. A **frontend UI label** for `InfraStack` (now renamed to "Stacks" tab).
2. A **field name** (`deployment_log` JSONB column on `InfraStack`).
3. A **verb** (`deploy_stack()`, `_provision_service()`).

### Entity hierarchy

```
StackBlueprint (recipe/template)
   |
   +-- deploy_stack() --> InfraStack (the deployed entity)
                             |-- StackService[]          (containers/pods)
                             |-- ServiceLink[]           (inter-service wiring)
                             |-- ServiceCredential[]     (admin access)
                             |-- DeployStep[]            (granular run telemetry)
                             |-- DevOpsLogEntry[]        (centralized infra log)
                             |-- DnsRecord[]             (DNS records)
                             +-- deployment_log          (JSONB event timeline)
```

### Rationale for not splitting

- `InfraStack` already contains all lifecycle state (`designing → queued → provisioning → ready/degraded/error → tearing_down`).
- A "re-deploy" mutates the same `InfraStack` in-place and creates new `DeployStep` records.
- Adding a `StackDeployment` entity would require duplicating the 1:N relationship to `StackService` and complicate every query.
- Historical revision tracking is available via `DeployStep` records (per-run, per-step).

### Related but SEPARATE system: Managed Instance Pool

`ManagedInstance` (table `managed_instances`) is a legacy K8s-based system, unrelated to `infra_stacks`. It stores K8s `Deployment` resource names. This is a K8s concept, not a domain entity. It is NOT wired into the infra-v2 pipeline.

---

## 2. Stack Independence from Project

`InfraStack.project_id` is nullable (`ondelete="SET NULL"`). Stacks can exist:

- **Standalone** (`mode="standby"`, `project_id=NULL`) — shared infrastructure, templates.
- **Project-bound** (`mode="project"`, `project_id=<pid>`) — engagement-specific.

### Bind/Unbind

- `POST /stacks/{sid}/bind` — attaches a standalone stack to a project.
- `POST /stacks/{sid}/unbind` — detaches without destroying infrastructure.

### Teardown isolation

- `close_project()` calls `destroy_stack()` only for stacks with `project_id == pid`.
- Standalone stacks are never affected by project closure.
- `DELETE /api/projects/{pid}` sets `project_id=NULL` on stacks (does NOT destroy cloud resources — known gap).

---

## 3. Post-Deploy Auto-Integration Pipeline

### Pipeline order (after ALL services deploy successfully)

| Step | Module | What | Blocking? |
|------|--------|------|-----------|
| Pre-deploy creds | `creds.pre_deploy_credentials` | Inject admin password into env | No (warn) |
| Firewall (per-svc) | `firewall.open_ports` | Open external ports on host | Soft (marks error) |
| Discovery | `discovery.discover_stack` | Match profiles, set health_url/admin_url | Yes → degraded |
| Links | `links.configure_all` | Write nginx proxy configs, Cloudflare DNS | Yes → degraded |
| Link verify | `links.verify_all` | HTTP probe links | No (warn) |
| Credentials | `creds.generate_for_stack` | Create ServiceCredential records | Yes → degraded |
| VPN | `vpn.setup_server` | WireGuard on k8s nodes | Yes → degraded |
| DNS | `dns.create_records_for_service` | Real DNS A records via provider | Yes → degraded |

### Integration status

Each `StackService` has `integration_steps` JSONB tracking per-step success/failure:
```json
{
  "discovery": {"status": "done", "ts": "..."},
  "links": {"status": "error", "message": "..."},
  "credentials": {"status": "done", "ts": "..."},
  "dns": {"status": "skipped", "reason": "no DNS provider"}
}
```

### Manual re-trigger

`POST /stacks/{sid}/integrate` — re-runs the full post-deploy pipeline for already-deployed services without re-deploying containers.

### Known gaps

1. ~~**No Host/Asset registration**~~ — **fixed 2026-09-15**: a project-bound stack's
   services register in the engagement Host graph as attacker-side hosts
   (`app/core/infra/host_registration.py`): one host per provider node IP with external
   ports (`443/tcp` style), tags `own-infra` / `infra-stack:{sid}` / `infra-role:{role}`,
   `is_attacker=True` + `import_source="infra-stack"` on rows the module creates (existing
   hosts are never flipped — tags/ports merge only). Registered from the post-deploy
   pipeline and on bind; unregistered on unbind and stack destroy (soft-delete when the
   row was ours and no other stack shares it).
2. **No C2 push-registration** — **partially fixed 2026-09-15 (Adaptix)**: redirectors linked
   to a C2 service via `http_proxy` register as listeners inside Adaptix automatically
   (`app/core/infra/c2_push.py`, blocking integration step `c2_listener_registration`,
   verified live against a teamserver). Mythic/Sliver push-registration remains open —
   their listener APIs are shape-different; the hook is per-framework on purpose.
3. ~~**`/redeploy` bypasses integration**~~ — **fixed 2026-09-15**: single-service
   redeploy runs the post-deploy pipeline for that service (firewall re-opens inside
   `_provision_service(force=True)`; discovery/links/creds/C2/VPN/DNS via
   `_run_post_deploy`), and the pipeline's outcome now drives the stack status:
   failure ⇒ `degraded` + `deployment_log` event + websocket refresh (previously the
   result was discarded and a failed integration left the stack "ready").
4. ~~**Two DNS paths**~~ — **fixed 2026-09-15**: `LinkManager._configure_dns` no longer
   runs its own inline cloudflare-only httpx call (which matched provider type
   `'cloudflare'` and therefore skipped real `cloudflare_dns` providers, left no
   `DnsRecord` row, and could not be cleaned up on teardown). Link DNS now goes through
   `DnsManager.upsert_domain_record` — provider adapters from `CloudProviderRegistry`
   (`cloudflare_dns`, `route53_dns`, …), records tracked as `DnsRecord` linked to the
   redirector service and removed by `delete_records_for_object` on destroy.
5. ~~**Project delete orphans stacks**~~ — **fixed 2026-09-15**: deletion now stamps bound
   stacks (`detached_at` / `detached_from_project`), notifies every active platform admin
   in-app, surfaces them via `GET /api/infra-v2/stacks?orphaned=true` and the Platform Ops
   "orphaned" filter, and a startup sweep repairs stacks detached by DB-level cascades.
   The cloud resources are still not destroyed automatically (deliberate) — destroy/re-bind
   stays an operator decision, but it is now visible.

---

## 4. DevOps Logging

### Model: `DevOpsLogEntry` (table `infra_devops_log`)

Centralized, persistent log for all infra operations, independent of stacks.

Fields: `id, stack_id, service_id, provider_id, level, category, message, details, actor, created_at`

### Sources

- `engine._log()` — mirrors `deployment_log` events to DevOps log.
- `StepTracker.complete/fail/skip` — mirrors step completions.
- Direct `log_event()` calls for ad-hoc events.

### Retention

Entries older than 90 days are auto-cleaned on each `GET /devops-log` call (configurable via `UMBRYX_DEVOPS_LOG_TTL_DAYS`).

### UI

Dedicated "DevOps" tab in PlatformOps with filters (stack, level, category), auto-refresh, and clear button.
