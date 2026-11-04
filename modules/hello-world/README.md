# Hello World Module

A demonstration extension module for the Umbryx modular architecture.

## What it shows

1. **Object types** — Defines a `greeting` object type with fields (title, message, priority, category, is_public, view_count). Objects are stored in the universal `core_objects` table — no custom table needed.

2. **Extension points** — Registers a sidebar nav item, a dashboard widget, and a project tab.

3. **Backend routes** — Adds custom API endpoints (`/api/ext/hello-world/stats`, `/api/ext/hello-world/greetings/{id}/view`) beyond the universal CRUD.

4. **Settings** — Declares configurable settings (max greetings, default priority, allow public).

## Structure

```
hello-world/
  manifest.yaml        # Module declaration
  backend/
    routes.py          # FastAPI router (exported as FASTAPI_ROUTER)
  README.md            # This file
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/modules/objects?type=greeting` | List greetings (universal CRUD) |
| POST | `/api/modules/objects` | Create greeting (universal CRUD) |
| GET | `/api/ext/hello-world/stats` | Aggregated greeting statistics |
| POST | `/api/ext/hello-world/greetings/{id}/view` | Increment view count |
