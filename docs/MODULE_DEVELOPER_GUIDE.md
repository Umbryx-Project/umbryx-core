# Umbryx Module Developer Guide

This guide covers building extension modules for the Umbryx platform.

## Quick Start

Create a directory under `/modules/` with a `manifest.yaml`:

```
modules/
  my-module/
    manifest.yaml
    backend/
      routes.py      # Optional: custom API routes
    README.md
```

The module is auto-discovered on backend startup. No registration code needed.

## Manifest Reference

The `manifest.yaml` is the single source of truth for a module's capabilities.

### Required Fields

```yaml
id: my-module            # lowercase, hyphens, [a-z0-9-]{2,63}
name: My Module          # display name
version: 1.0.0           # semantic versioning
```

### Metadata

```yaml
description: >
  What this module does.
author: Your Name
license: MIT
icon: server             # icon name from the Icon component
```

### Dependencies

```yaml
depends_on:
  - topology             # other module IDs that must be present
conflicts_with:
  - old-module           # modules that cannot coexist
```

### Permissions

Declare what data your module needs to access:

```yaml
permissions:
  - read:hosts           # read host data
  - write:findings       # create/update findings
  - exec:jobs            # execute jobs
  - write:object         # write to universal object model
```

Valid modes: `read`, `write`, `exec`
Valid scopes: `hosts`, `creds`, `findings`, `scopes`, `loot`, `jobs`, `notes`, `networks`, `tasks`, `object`, `settings`

### Object Types

Define typed objects stored in the universal `core_objects` table:

```yaml
objects:
  - type: vulnerability      # unique type identifier
    name: Vulnerability      # display name
    icon: bug
    list_columns: [title, severity, status]   # columns in auto-generated list view
    fields:
      - name: title
        type: string
        label: Title
        required: true
      - name: severity
        type: enum
        label: Severity
        options: [low, medium, high, critical]
        default: medium
      - name: cvss_score
        type: float
        label: CVSS Score
      - name: description
        type: text
        label: Description
      - name: is_exploitable
        type: boolean
        label: Exploitable
        default: false
      - name: remediation
        type: text
        label: Remediation
      - name: related_finding
        type: reference
        label: Related Finding
        reference_type: finding     # references another object type
      - name: metadata
        type: json
        label: Metadata
```

**Field types:** `string`, `text`, `integer`, `float`, `boolean`, `enum`, `datetime`, `json`, `reference`

Objects are accessible via the universal CRUD API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules/objects?type=vulnerability` | List objects |
| POST | `/api/modules/objects` | Create object |
| GET | `/api/modules/objects/{id}` | Get object |
| PATCH | `/api/modules/objects/{id}` | Update object |
| DELETE | `/api/modules/objects/{id}` | Delete object |

### Extension Points

Register UI extensions:

```yaml
extensions:
  sidebar.nav:
    - id: my-view
      label: My View
      icon: bolt
      view: myView

  project.tab:
    - id: project-items
      label: Items
      icon: list

  dashboard.widget:
    - id: stats-widget
      label: Statistics
      component: StatsWidget

  host.tab:
    - id: host-details
      label: My Tab

  settings.section:
    - id: my-settings
      label: Module Settings

  report.section:
    - id: my-report
      label: Custom Section

  actions.host:
    - id: scan-host
      label: Scan
      icon: target

  importer:
    - id: csv-import
      label: Import CSV
      accept: .csv

  search.provider:
    - id: search-items
      label: Search Items
```

**Known extension points:** `sidebar.nav`, `project.tab`, `host.tab`, `network.tab`, `dashboard.widget`, `settings.section`, `report.section`, `actions.host`, `actions.finding`, `actions.cred`, `actions.object`, `importer`, `search.provider`

### Navigation Placement (Required for `sidebar.nav`)

The sidebar uses a **2-level hierarchy**: 7 semantic groups, each containing related sections. When registering a new `sidebar.nav` extension, you **must** declare which group your item belongs to:

```yaml
extensions:
  sidebar.nav:
    - id: my-view
      label: My View
      icon: bolt
      view: myView
      nav_group: Recon      # REQUIRED — one of the groups below
```

**Existing navigation groups:**

| Group | Purpose | Current sections |
|-------|---------|-----------------|
| *(Overview)* | Project selection and dashboard | Projects, Overview |
| Recon | Discovery and scanning | Hosts, Scope, Scans |
| Exploit | Exploitation evidence and access | Creds, Findings, Loot, Notes |
| Visualize | Graphs and analysis | Network, Attack Path, Attack Graph |
| Automate | Automation and execution | Jobs, Playbooks, Automations, Commands |
| Infra | Infrastructure management | Platform Ops, Workstations, ROE |
| Output | Reporting and tracking | Objectives, Checklist, KB, Timeline, Report |

**Rules:**

1. **Prefer embedding over new nav items.** Before adding a `sidebar.nav` entry, consider whether the functionality can be delivered as a `host.tab`, `dashboard.widget`, `actions.host`, or inline button in an existing section. A button on the relevant object card is almost always better than a new top-level page.

2. **Always specify `nav_group`.** If omitted, the item will not appear in the sidebar. Choose the group that best matches the user's mental model — where would a user *look for* this feature?

3. **New groups require justification.** Adding a new top-level group is a significant UX change. Only justified when:
   - The module introduces a fundamentally new workflow phase (not covered by existing groups)
   - There are 3+ related sections that don't fit any existing group
   - The module lead + UX reviewer approve

4. **One item per module.** A module should contribute at most one `sidebar.nav` entry. Additional functionality should be embedded via other extension points (`host.tab`, `dashboard.widget`, etc.).

5. **Prefer contextual integration.** For AI/ML features: use `actions.*` extension points to add "Ask AI" buttons on object cards rather than creating a separate AI section. Only create a dedicated section if the module provides a full workspace (chat interface, agent orchestration, etc.).

### Visual Consistency

All module UI must use the shared color and status glossary from `src/constants.js`:

| Import | Purpose |
|--------|---------|
| `NODE_STATUS` | Host status colors (unknown/alive/scanned/access/pwned/owned) |
| `SEVERITY` | Finding severity colors (critical/high/medium/low/info) |
| `FINDING_STATUS` | Finding lifecycle status colors |
| `OBJECTIVE_STATUS` | Objective status colors |
| `ACTIVITY_TYPES` / `ACTIVITY_STATUS` | From `utils/hosts.js` — activity log colors |

**Never hardcode color hex values.** Import from `constants.js` or `utils/hosts.js`. If you need a new status/severity level, add it to the canonical source first, then import.

**Icon names** must match keys in `src/components/Icon.jsx`. Use `icon:` in manifest YAML to specify the icon for nav items and object types.

### Navigation Review Process

The sidebar structure (`TAB_GROUPS` in `src/constants.js`) should be reviewed:
- After every 3 new modules added
- Or once per quarter (whichever comes first)

Review checklist:
1. Does any group have more than 5 items? Consider splitting.
2. Are there items that users struggle to find? Check support tickets/anecdotal feedback.
3. Are there groups with only 1 item? Consider merging into a related group.
4. Has a new workflow phase emerged that doesn't fit any existing group?

### Settings

Declare configurable settings:

```yaml
settings:
  - key: max_items
    label: Maximum Items
    type: integer
    default: 100
    description: Maximum number of items per project
  - key: api_key
    label: API Key
    type: string
    placeholder: "Enter your API key"
  - key: enabled_features
    label: Features
    type: enum
    options: [basic, advanced, enterprise]
    default: basic
```

### Backend Routes

Add custom API endpoints:

```yaml
route_prefix: /api/ext/my-module
backend_entry: routes    # resolves to backend/routes.py
```

Create `backend/routes.py`:

```python
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.core_object import CoreObject

router = APIRouter(prefix="/api/ext/my-module", tags=["my-module"])

@router.get("/custom-endpoint")
def my_endpoint(db: Session = Depends(get_db)):
    return {"status": "ok"}

# The loader looks for this attribute
FASTAPI_ROUTER = router
```

The router is automatically mounted on the FastAPI app at startup.

## Universal Object Model

The `core_objects` table provides schema-driven storage without creating custom tables:

```python
from app.models.core_object import CoreObject
from app.core.modules import obj_type_registry

# Validate data against schema
errors = obj_type_registry.validate_data("vulnerability", data)

# Create object
obj = CoreObject(
    id="vuln_001",
    type="vulnerability",
    module_id="my-module",
    name=data.get("title"),
    data=data,
)
db.add(obj)
db.commit()
```

### Relations

Objects can have typed relationships:

```python
# Add relation
obj.relations["affects"] = [{"id": "host_123", "weight": "high"}]
db.commit()

# Query via API
GET /api/modules/objects/{id}/relations/affects
```

## Frontend Integration

### ExtensionSlot Component

Render extensions registered by modules:

```jsx
import ExtensionSlot from '../modules/ExtensionSlot.jsx';

// Render all dashboard widgets from modules
<ExtensionSlot
  point="dashboard.widget"
  render={(entry) => (
    <div key={entry.id}>
      <h3>{entry.label}</h3>
      {/* Render widget based on entry.component */}
    </div>
  )}
/>
```

### GenericObjectView Component

Schema-driven CRUD UI for any object type:

```jsx
import GenericObjectView from '../modules/GenericObjectView.jsx';

<GenericObjectView objectType="vulnerability" projectId={pid} accent={accent} />
```

### Error Boundaries

Module components are wrapped in error boundaries automatically by ExtensionSlot.
To manually isolate a module component:

```jsx
import ModuleErrorBoundary from '../modules/ModuleErrorBoundary.jsx';

<ModuleErrorBoundary moduleName="my-module">
  <MyComponent />
</ModuleErrorBoundary>
```

## API Reference

### Module Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/modules` | any | List all modules |
| POST | `/api/modules/{id}/enable` | admin | Enable module |
| POST | `/api/modules/{id}/disable` | admin | Disable module |
| GET | `/api/modules/{id}/health` | any | Health check |

### Object Types

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules/object-types` | List all type schemas |
| GET | `/api/modules/object-types/{type}` | Get schema for a type |

### Extensions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules/extensions` | All extension entries |
| GET | `/api/modules/extensions/{point}` | Entries for a specific point |

### Object CRUD

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules/objects` | List (filter by type, project_id, status) |
| POST | `/api/modules/objects` | Create |
| GET | `/api/modules/objects/{id}` | Get |
| PATCH | `/api/modules/objects/{id}` | Update |
| DELETE | `/api/modules/objects/{id}` | Delete |
| POST | `/api/modules/objects/{id}/relations` | Add relation |
| GET | `/api/modules/objects/{id}/relations/{type}` | Get relations |

## Core vs Extension Boundary

### Core (not extractable)
- Authentication & authorization (`auth`, `core/deps`, `core/security`)
- User & organization management (`users`, `organizations`, `projects`)
- Database & session management (`database.py`, `alembic`)
- Event system (`core/events`, `ws`)
- Settings & configuration (`core/config`, `core/enums`)
- Logging (`core/logging_setup`)
- Error handling (`core/errors`)
- Module framework itself (`core/modules`)

### Extension candidates
- Infrastructure provisioning (`core/infra/*`)
- AI assistant (`routers/ai`)
- Attack graph & topology (`routers/attack_graph*`, `routers/topology`)
- DNS management (`routers/dns`)
- Scan importers (`routers/import_scanners`)
- C2 integration (`routers/c2`)
- Playbooks (`routers/playbooks`)
- Reports (`routers/report`)
- Marketplace (`routers/marketplace`)

## Module Discovery Flow

1. Backend scans `/modules/*/manifest.yaml` on startup
2. Each manifest is parsed and validated
3. Dependencies and conflicts are checked
4. Object types registered in `obj_type_registry`
5. Extension points registered in `ext_registry`
6. Backend entry points imported (FASTAPI_ROUTER mounted)
7. Frontend fetches `/api/modules/extensions` on auth
8. `ExtensionSlot` components render registered extensions

## Lifecycle

Modules can be enabled/disabled at runtime via the admin API:

```bash
# Disable
curl -X POST -b "rt_auth=TOKEN" http://localhost:8080/api/modules/my-module/disable

# Enable
curl -X POST -b "rt_auth=TOKEN" http://localhost:8080/api/modules/my-module/enable

# Health check
curl -b "rt_auth=TOKEN" http://localhost:8080/api/modules/my-module/health
```

Disabling unregisters all object types and extension entries for that module.
Existing data in `core_objects` is preserved.

## Real-World Migration Examples

### Pattern 1: Settings-only module (AI Assistant)

For features that already have backend code and just need formal registration:

```yaml
# modules/ai-assistant/manifest.yaml
id: ai-assistant
name: AI Assistant
version: 1.0.0
description: AI-powered security assistant with multi-provider LLM support.
permissions:
  - read:hosts
  - read:findings
extensions:
  settings.section:
    - id: ai-providers
      label: AI Providers
      component: AISection
settings:
  - key: provider
    label: Default Provider
    type: enum
    options: [anthropic, openai, groq, mistral, openrouter, ollama, litellm]
    default: anthropic
```

**What happened:** The backend code (`routers/ai.py`, `core/ai_manager.py`) was already wired in `main.py`. The manifest only declares metadata, permissions, settings, and extension points. No code was moved. The module appears in System → Modules and its settings are discoverable.

### Pattern 2: Object type declaration (DNS Management)

For features with structured data that fits the universal object model:

```yaml
# modules/dns-management/manifest.yaml
objects:
  - type: dns_record
    name: DNS Record
    list_columns: [hostname, record_type, value, provider]
    fields:
      - name: hostname
        type: string
        required: true
      - name: record_type
        type: enum
        options: [A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR]
        default: A
      - name: value
        type: string
        required: true
      - name: provider
        type: enum
        options: [manual, cloudflare]
        default: manual
```

**What happened:** DNS records previously had a custom table (`dns_records`). The manifest declares a `dns_record` object type. New records can be created via the universal CRUD API (`POST /api/modules/objects`) and rendered with `GenericObjectView`. The existing table stays for backward compatibility during migration.

### Pattern 3: Extension point wiring (ROE)

For features that provide a project-scoped tab:

```yaml
# modules/roe/manifest.yaml
id: roe
name: Rules of Engagement
version: 1.0.0
extensions:
  project.tab:
    - id: roe
      label: ROE
      icon: scroll
```

**What happened:** ROE already had a backend router and frontend view (`RoeView.jsx`). The manifest declares the `project.tab` extension point so the module system knows this module provides a project-level tab. The tab wiring in `AppTabRouter.jsx` stays as-is during the transition period.

## Migration Checklist

When migrating an existing feature to a module:

- [ ] Create `modules/<name>/manifest.yaml` with metadata, permissions, objects, extensions, settings
- [ ] Verify module appears in System → Modules panel
- [ ] Verify object types appear at `GET /api/modules/object-types`
- [ ] Verify extension points appear at `GET /api/modules/extensions`
- [ ] Run module validator: `python3 -c "from app.core.modules import *; from app.core.modules.manifest import Manifest; m = Manifest.from_file(Path('modules/<name>/manifest.yaml')); from app.core.modules.validator import validate_module; print(validate_module(m))"`
- [ ] If the module has custom API routes, create `backend/routes.py` exporting `FASTAPI_ROUTER`
- [ ] Test enable/disable lifecycle: `POST /api/modules/<name>/disable` then `/enable`
- [ ] Update this guide with the migration pattern used
