"""C2 operations — listeners, payloads, framework dispatch.

Lives in core, not in the infra package, because operating a C2 is not
deploying one. Integrations are stored as a global settings list and a
teamserver the operator stands up themselves is reachable without Umbryx
having provisioned anything (docs/modules/EDITIONS.md) — the same
reasoning that keeps attacker-SSH in Community Edition.

The one part that genuinely needs the deployment layer is exposing a
listener's port on a C2 that Umbryx deployed: patching a Kubernetes
Service live, or reporting that a Docker container needs a recreate. That
path requires an integration bound to a StackService, so it is
unreachable in Community, and it reaches the Enterprise package through
the editions seam rather than importing it.
"""
