# Umbryx Module Registry — Full Audit & Classification

**Date:** 2026-07-11
**Status:** Living document — updated as migration progresses.

---

## Methodology

Each functional unit was identified by scanning:
- Formal plugin systems (`app/plugins/`, `app/core/modules/`)
- Informal decorator registries (`@Registry.register`)
- All routers (68 files in `app/routers/`)
- All models (35 files, ~85 tables)
- All frontend views (39 files + subdirectories)
- Frontend nav structure (`constants.js`, `zones.js`, `AppTabRouter.jsx`)

Classification criteria:
- **Core** — dependency for other parts, critical for basic operation, stable
- **Extension** — optional, isolatable, specific functionality
- **Deprecated** — dead code, duplicated, or unreachable

---

## Section A: Formal Plugin Modules (BackendModule system)

4 builtin BackendModules registered in `app/plugins/loader.py`.

| # | Module | Description | Verdict | Rationale |
|---|--------|-------------|---------|-----------|
| A1 | `topology` | Network topology builder from scan imports | **Extension** | Self-contained subsystem. Gated by `registry.get("topology")` in routes. Has its own router package (`routers/topology/`). Depends on Core (network model, scan data). Can be disabled without breaking base functionality. |
| A2 | `nmap_parser` | Nmap XML parser + scan tool connectors (nmap, nuclei, netexec, httpx, ffuf, donpapi) | **Extension** | The connector metadata and scan parser are used by playbook validation and the connector catalog. However, the actual parsing logic lives in topology routes, not in the module itself. Can be extracted as a "scan tools" extension. |
| A3 | `attacker_ssh` | Remote SSH execution on attacker box | **Extension** | Self-contained execution subsystem. Config stored in `global_settings.attacker_ssh_config`. Gated by `registry.get("attacker_ssh")` in 5 routers. Can be disabled (users lose remote exec but everything else works). |
| A4 | `c2_integration` | C2 framework sync (Sliver, Mythic, Adaptix; Cobalt Strike — webhook ingestion only, live sync post-1.0) | **Extension** | Fully self-contained. Router package `routers/c2/` (7 files). Gated by `registry.get("c2_integration")`. Has auto-sync background loop. Can be disabled — users lose C2 sync, no other functionality breaks. |

---

## Section B: Informal Decorator Registries

These use the `@Registry.register("type")` pattern — the most mature extension pattern in the codebase.

| # | Registry | Base class | Registered items | Verdict | Rationale |
|---|----------|-----------|-----------------|---------|-----------|
| B1 | CloudProviderRegistry | `cloud_provider.py:CloudProvider` | ssh_host, hetzner, proxmox, aws | **Extension (each adapter)** | Each cloud provider adapter is independently optional. The registry ABC itself is Core. |
| B2 | DeployMethodRegistry | `deploy_method.py:DeployMethod` | ssh, docker, k8s, terraform | **Extension (each method)** | Same pattern. Each deploy method is independently optional. Registry ABC is Core. |
| B3 | ProviderRegistry (legacy) | `provider_adapter.py:ProviderAdapter` | ssh, docker, k8s | **Deprecated** | Superseded by B1+B2 (bridge methods already in engine.py). Still present for backward compat but `_bridge_deploy`/`_bridge_destroy` try new system first, fall back to this. Should be removed after full migration. |
| B4 | DNS Provider Registry | `dns/manager.py` | manual, Cloudflare (not auto-registered) | **Extension** | DNS management is optional. `dns` nav tab is currently dead (not rendered in AppTabRouter). Can be packaged as an extension module. |
| B5 | Storage Backend | `storage.py:StorageBackend` | Local, S3 | **Core** | File storage is a Core dependency (loot, attachments, evidence). The S3 adapter could theoretically be an extension, but Local is essential. Keep both in Core. |
| B6 | AI Provider Manager | `ai_manager.py` | anthropic, openai, groq, mistral, openrouter, ollama, litellm | **Extension** | AI assistant is optional functionality. Config-driven, self-contained. Depends on Core (config) only. |
| B7 | Notification Dispatcher | `notifications.py` | Telegram, Slack, Webhook | **Extension** | Notifications are optional. Config-driven, fire-and-forget. Depends on Core (config, events) only. |

---

## Section C: Routers — Classification

68 routers in `app/routers/`. Classification below.

### Core Routers (stay in base platform)

| Router | Prefix | Rationale |
|--------|--------|-----------|
| `auth` | `/api/auth` | Authentication is Core |
| `admin` | `/api/admin` | User management is Core |
| `system_api` | `/api/system` | System info is Core |
| `system_metrics` | `/api/system` | Metrics are Core |
| `system_modules` | `/api/admin/modules` | Module management is Core (but manages extensions) |
| `audit` / `audit_api` | `/api/admin/audit`, `/api/audit` | Audit trail is Core |
| `plugins` | `/api/plugins` | Plugin bundle management is Core infrastructure |
| `modules_api` | `/api/modules` | Manifest module system is Core infrastructure |
| `organizations` | `/api/orgs` | Org/team management is Core |
| `projects` | `/api/projects` | Projects are Core |
| `members` | `/api/projects` | Membership is Core |
| `hosts` | `/api/hosts` | Host inventory is Core |
| `creds` | `/api/creds` | Credential management is Core |
| `notes` | notes | Notes are Core |
| `findings` | `/api/findings` | Findings are Core |
| `networks` | `/api/networks` | Networks are Core |
| `search` | search | Search is Core |
| `notifications` | `/api/notifications` | In-app notifications are Core |
| `secrets` | secrets | Project secrets are Core |
| `encryption` | `/api/system/encryption` | Encryption key mgmt is Core |
| `snapshots` | snapshots | Snapshots are Core |
| `timeline` | `/api/timeline` | Timeline is Core |
| `sync_api` | `/api/sync` | Data sync is Core infrastructure |
| `dashboards_api` | dashboards | Dashboard aggregation is Core |
| `import_export` | import-export | Project import/export is Core |
| `project_templates` | `/api/project-templates` | Templates are Core |
| `tasks_api` | tasks | Task management is Core |
| `import_scanners` | import_scanners | Scan import pipeline is Core (consumed by topology extension) |
| `creds_host_notes` | `/api/cred-host-notes` | Cred×host matrix is Core |
| `checklist` | `/api/checklist` | Checklist is Core |
| `activities` | `/api/host-activities` | Activity log is Core |
| `collections` | collections | Host collections are Core |
| `loots` | `/api/loots` | Loot/evidence is Core |
| `scopes` | `/api/scopes` | Scope mgmt is Core |
| `domains` | `/api/domains` | AD domains are Core |
| `objectives` | `/api/objectives` | Objectives are Core |

### Extension Routers (candidates for module extraction)

| Router | Prefix | Extension candidate | Rationale |
|--------|--------|---------------------|-----------|
| `topology/` | topology | topology | Self-contained, gated by plugin |
| `c2/` | `/api/admin/c2` | c2-integration | Self-contained, gated by plugin |
| `playbooks/` | playbooks | playbooks | Self-contained engine with its own model |
| `scheduled_playbooks` | `/api/scheduled-playbooks` | playbooks | Depends on playbooks |
| `scans` | scans | attacker-exec | Depends on attacker_ssh plugin |
| `bulk_actions` | bulk | attacker-exec | Depends on attacker_ssh |
| `attacker_exec` | attacker-exec | attacker-exec | Directly tied to attacker_ssh |
| `dns` | `/api/dns` | dns-management | Frontend tab is dead. Optional subsystem. |
| `ai` | ai | ai-assistant | Optional AI functionality |
| `attack_graph` / `attack_graph_api` | attack-graph | attack-graph | Optional visualization layer |
| `attack_paths` | attack-paths | attack-graph | Part of attack graph subsystem |
| `kb` | `/api/kb` | knowledge-base | Optional knowledge base |
| `mitre` | mitre | mitre-coverage | Reference data, optional |
| `report` | report | reporting | Optional report generation |
| `webhooks` | webhooks | webhooks | Optional webhook ingestion |
| `workstations` | `/api/workstations` | workstations | Optional workstation provisioning |
| `infra_v2_api` | `/api/infra-v2` | infra-v2 | Large infra subsystem |
| `marketplace` | `/api/marketplace` | marketplace | Service templates + org plans |
| `image_registries` | `/api/image-registries` | infra-v2 | Part of infra subsystem |
| `instance_templates_api` | instance-templates | infra-v2 | Part of infra subsystem |
| `managed_instances_api` | managed-instances | infra-v2 | Part of infra subsystem |
| `instance_credentials_api` | instance-credentials | infra-v2 | Part of infra subsystem |
| `roe` | roe | roe | Optional rules of engagement |
| `closure` | closure | closure | Optional project closure |
| `export` | export | reporting | Part of reporting |
| `import_bloodhound` | import_bloodhound | bloodhound-import | Optional BloodHound import |
| `pivots` | pivots | pivots | Optional pivot tracking |

### Deprecated / Dead Routers

| Router | Verdict | Rationale |
|--------|---------|-----------|
| (none fully dead) | — | All 68 routers are included in `main.py`. But `dns` is unreachable from frontend. |

---

## Section D: Frontend Views — Classification

### Dead / Orphaned Views

| View | File | Verdict | Action |
|------|------|---------|--------|
| `DNSView` | `views/DNSView.jsx` | **Deprecated** | Tab exists in constants but not in AppTabRouter. Fully implemented but never rendered. Either wire it in or remove the tab + view. |
| `MitreView` | `views/MitreView.jsx` | **Deprecated** | Fully implemented but never imported/rendered. MITRE coverage is embedded inside KB view instead. |
| `InstancePoolView` | `views/InstancePoolView.jsx` | **Deprecated** | Full instance-pool UI but never rendered. Superseded by infra-v2 PlatformOpsView. |

### Core Views

| View | Tab | Rationale |
|------|-----|-----------|
| `ProjectsView` | projects | Core entity management |
| `OverviewView` | overview | Dashboard |
| `HostsView` | hosts | Core entity |
| `CredsView` | creds | Core entity |
| `FindingsView` | findings | Core entity |
| `NotesView` | notes | Core entity |
| `NetworkView` | network | Core entity |
| `ScopeView` | scope | Core entity |
| `ChecklistView` | checklist | Core entity |
| `ObjectivesView` | objectives | Core entity |
| `LootView` | loot | Core entity |
| `TimelineView` | timeline | Core entity |
| `AdminView` | admin | Platform admin |
| `SystemDashboard` | system | System monitoring |
| `OrganizationsView` | organizations | Org management |
| `AuditView` | audit | Audit trail |
| `UserSettingsView` | user-settings | User prefs |
| `LoginView` | (auth gate) | Authentication |
| `SearchModal` | (overlay) | Search |
| `ImportModal` | (overlay) | Import |

### Extension Views (candidates for module extraction)

| View | Tab | Extension module | Rationale |
|------|-----|-----------------|-----------|
| `PlatformOpsView` (+5 sub-tabs) | platform-ops | infra-v2 | Self-contained infra subsystem |
| `WorkstationsView` | workstations | workstations | Optional workstation provisioning |
| `ScansView` (+C2/Webhook panels) | scans | attacker-exec + c2 | Tied to plugin system |
| `JobsView` | jobs | jobs | Could be Core (used by many) or Extension |
| `PlaybooksView` | playbooks | playbooks | Self-contained engine |
| `CheatsheetView` | cheatsheet | attacker-exec | Tied to attacker SSH |
| `AttackPathView` | attackpath | attack-graph | Optional visualization |
| `AttackGraphView` | attackgraph | attack-graph | Optional visualization |
| `KBView` | kb | knowledge-base | Optional reference data |
| `ReportView` | report | reporting | Optional |
| `RoeView` | roe | roe | Optional |
| `DashboardView` | dashboards | dashboards | Hidden, programmatic |
| `AIChatPanel` | (overlay) | ai-assistant | Optional AI |
| `ClosureWizard` | (in Projects) | closure | Optional |

---

## Section E: Models — Classification

### Core Models (~50 tables)

`auth.py`, `organization.py`, `organization_plan.py`, `project.py`, `host.py`, `cred.py`, `domain.py`, `note.py`, `network.py`, `finding.py`, `entity_link.py`, `loot.py`, `scope.py`, `objective.py`, `job.py` (partial), `timeline.py`, `secret.py`, `encryption_key.py`, `snapshot.py`, `system_log.py`, `audit.py`, `notification.py`, `task.py`, `metric.py`, `sync.py`, `core_object.py`

### Extension Models (~35 tables)

| Model file | Tables | Extension module |
|-----------|--------|-----------------|
| `attack.py` | attack_paths, attack_steps, attack_path_nodes, attack_path_edges, attack_path_branches, attack_path_versions | attack-graph |
| `kb.py` | kb_articles, custom_snippets | knowledge-base |
| `dns.py` | dns_records | dns-management |
| `decommission.py` | decommission_reports | closure |
| `workstation.py` | workstation_templates, operator_workstations, infra_events | workstations |
| `instance_pool.py` | instance_templates, managed_instances, instance_credentials | infra-v2 |
| `infra_v2.py` | 12 tables | infra-v2 |
| `installed_plugin.py` | installed_plugins | plugin-bundles (Core infrastructure) |

---

## Section F: SDK Contracts

| Component | Verdict | Rationale |
|-----------|---------|-----------|
| `sdk/contracts.py` Protocols | **Aspirational** | Defined but zero runtime implementations. Should be aligned with the new manifest module system. |
| `sdk/events.py` event_bus | **Core** | Event bus is Core infrastructure. Only one consumer (closure) but the pattern is sound. |
| `plugins/bundle_loader.py` | **Core infrastructure** | `.rnplugin` installation. Should integrate with new manifest system. |
| `plugins/state.py` attacker_ssh_config | **Extension** | Part of attacker-exec extension. Currently mixed into Core module management. |

---

## Section G: Conflicting / Overlapping Functionality

| Conflict | Components | Resolution |
|----------|-----------|------------|
| G1: Two plugin systems | BackendModule (`plugins/`) vs Manifest (`core/modules/`) | **Merge**: BackendModule becomes the runtime API; Manifest wraps it with declarative metadata. Bridge: manifest loader creates BackendModule entries. |
| G2: Legacy provider adapters | `provider_adapter.py` ProviderRegistry vs `cloud_provider.py` + `deploy_method.py` | **Remove legacy**: Bridge methods in engine.py already prefer the new system. Remove after full migration. |
| G3: DNS dead tab | `dns` in TABS but not in AppTabRouter; DNSView.jsx orphaned | **Remove tab from constants** or **wire it in**. Recommend remove until DNS module is properly migrated. |
| G4: Module management split | `system_modules.py` (old), `modules_api.py` (new), `plugins.py` (bundles) | **Consolidate**: One API surface for all module types. |
| G5: Frontend module registry inert | `features/plugins/registry.js` has getters but no view consumes them | **Wire up**: ExtensionSlot component already exists — need to add it to views. |
| G6: Instance pool vs infra-v2 | `InstancePoolView` orphaned, superseded by infra-v2 | **Remove InstancePoolView** and old instance pool routers if infra-v2 is the replacement. |

---

## Section H: Gap Analysis — Extension Candidates

Ranked by migration difficulty.

### Easy (manifest + minor restructuring)

| # | Extension | Current state | Gap | Effort |
|---|-----------|--------------|-----|--------|
| H1 | **DNS Management** | Dead frontend tab + working backend router (`dns.py`) + model (`dns.py`) + DNS provider registry | Need: manifest.yaml, wire frontend tab in AppTabRouter, clean up provider registry. All code exists, just needs packaging. | **2h** |
| H2 | **AI Assistant** | Backend: `routers/ai.py` + `core/ai_manager.py` + `core/ai_tools.py`. Frontend: `AIChatPanel.jsx` (overlay). | Need: manifest.yaml declaring sidebar.nav + settings. Already self-contained. No custom DB tables. | **1h** |
| H3 | **Notifications (channels)** | Backend: `core/notifications.py` (Telegram/Slack/Webhook). Frontend: AdminView section. | Need: manifest.yaml declaring settings.section. Config-driven, no custom tables. | **1h** |
| H4 | **Reporting** | Backend: `routers/report.py` + `routers/export.py`. Frontend: `ReportView.jsx`. | Need: manifest.yaml. No custom DB tables (reads cross-model). | **1h** |
| H5 | **ROE** | Backend: `routers/roe.py`. Frontend: `RoeView.jsx`. Model: `organization.ProjectROE` (1 table). | Need: manifest.yaml declaring project.tab. | **1h** |

### Medium (need some code separation)

| # | Extension | Current state | Gap | Effort |
|---|-----------|--------------|-----|--------|
| H6 | **C2 Integration** | Backend: `routers/c2/` (7 files) + plugin module. Frontend: `scans/C2Panel.jsx`. No custom tables. | Need: move c2 code into `modules/c2-integration/`, create manifest, wire extension points. Plugin already registered in BackendModule. | **4h** |
| H7 | **Attacker SSH** | Backend: `routers/attacker_exec.py`, `bulk_actions.py`, `cheatsheet` logic + plugin module. Frontend: `CheatsheetView.jsx`, scan execution. | Need: consolidate attacker-related code, create manifest. Plugin already registered. | **4h** |
| H8 | **Knowledge Base** | Backend: `routers/kb.py`. Model: `kb.py` (2 tables). Frontend: `KBView.jsx`. | Need: manifest, move model into module. | **3h** |
| H9 | **Closure** | Backend: `routers/closure.py`. Model: `decommission.py` (1 table). Frontend: `ClosureWizard.jsx`. | Need: manifest, model extraction. Uses `event_bus` (only consumer). | **3h** |
| H10 | **Topology** | Backend: `routers/topology/` (7 files) + plugin module. Model: `network.py` (shared). Frontend: embedded in NetworkView. | Need: manifest. Model is shared with Core — tricky boundary. | **4h** |

### Hard (deeply intertwined with Core)

| # | Extension | Current state | Gap | Effort |
|---|-----------|--------------|-----|--------|
| H11 | **Infra v2** | Backend: `routers/infra_v2_api.py` (56KB!) + `core/infra/` (15+ files) + 6 infra routers. Model: `infra_v2.py` (12 tables). Frontend: `PlatformOpsView` (5 sub-tabs). | Massive. Need major refactoring to separate from Core. Decorator registries add complexity. | **2-3 days** |
| H12 | **Workstations** | Backend: `routers/workstations.py` + `core/workstation/`. Model: `workstation.py` (3 tables). Frontend: `WorkstationsView.jsx`. | Moderate, but shares infra provider code with infra-v2. | **1 day** |
| H13 | **Attack Graph** | Backend: `routers/attack_graph.py`, `attack_graph_api.py`, `attack_paths.py`. Model: `attack.py` (6 tables). Frontend: `AttackPathView.jsx`, `AttackGraphView.jsx`. | Moderate complexity. Shares entity_link model with Core. | **1 day** |
| H14 | **Playbooks** | Backend: `routers/playbooks/` (5 files) + `scheduled_playbooks.py`. Model: `job.py` (shared with Core jobs). Frontend: `PlaybooksView.jsx` (complex). | Playbook model shares the `jobs` table with Core. Need to separate playbook-specific fields. | **1-2 days** |
| H15 | **Marketplace** | Backend: `routers/marketplace.py`. Model: `organization_plan.py`. Frontend: none (API only). | Tied to org billing — needs careful boundary. | **4h** |

---

## Section I: Deprecated — Removal List

| # | Component | Action | Risk |
|---|-----------|--------|------|
| I1 | `DNSView.jsx` (orphaned) | Remove file OR wire into AppTabRouter | Low — not rendered |
| I2 | `MitreView.jsx` (orphaned) | Remove file (MITRE covered by KB) | Low — not rendered |
| I3 | `InstancePoolView.jsx` (orphaned) | Remove file (superseded by infra-v2) | Low — not rendered |
| I4 | `dns` tab in constants.js/zones.js | Remove tab entry (dead nav) | Low — blank pane currently |
| I5 | `provider_adapter.py` legacy registry | Remove after bridge methods confirmed stable | Medium — engine.py falls back to it |
| I6 | `sdk/contracts.py` Protocols | Align with manifest system or remove | Low — zero consumers |
| I7 | `plugins/modules/` auto-created empty dir | Leave as-is (harmless) | None |
