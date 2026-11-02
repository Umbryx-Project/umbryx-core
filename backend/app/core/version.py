"""Platform version — the single source of truth for the running build.

Bumped by the release commit (see CHANGELOG / RELEASE_NOTES.md). Surfaced
by GET /api/system/edition and shown in the UI so an operator can tell
which build a stand runs without digging for the image tag.
"""

PLATFORM_VERSION = "0.10.0"
