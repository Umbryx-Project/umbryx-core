"""
Domain-grouped router registration.

Each function registers all routers for a logical domain.
Call ``register_all(app)`` from main.py to wire everything.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _register_auth(app):
    from .routers import (
        admin,
        auth,
        members,
        oidc_admin,
        oidc_auth,
        oidc_platform_admin,
        organizations,
        project_access,
        proxies_admin,
    )
    from .routers import audit as audit_router
    from .routers import audit_api as audit_api_router

    app.include_router(auth.router)
    app.include_router(admin.router)
    app.include_router(proxies_admin.router)
    app.include_router(project_access.router)
    app.include_router(members.router)
    app.include_router(organizations.router)
    app.include_router(oidc_admin.router)
    app.include_router(oidc_platform_admin.router)
    app.include_router(oidc_auth.router)
    app.include_router(audit_router.router)
    app.include_router(audit_api_router.router)


def _register_system(app):
    from .routers import (
        image_registries,
        license_admin,
        marketplace,
        modules_api,
        plugins,
        system_api,
        system_metrics,
        system_modules,
        user_ssh_keys,
    )

    app.include_router(system_api.router)
    app.include_router(system_metrics.router)
    app.include_router(system_modules.router)
    app.include_router(plugins.router)
    app.include_router(image_registries.router)
    app.include_router(marketplace.router)
    app.include_router(license_admin.router)
    app.include_router(modules_api.router)
    app.include_router(user_ssh_keys.router)
    app.include_router(user_ssh_keys.admin_router)


def _register_projects(app):
    from .routers import (
        domains,
        objectives,
        project_templates,
        projects,
        roe,
        scopes,
    )

    app.include_router(projects.router)
    app.include_router(roe.router)
    app.include_router(scopes.router)
    app.include_router(domains.router)
    app.include_router(objectives.router)
    app.include_router(project_templates.router)


def _register_hosts(app):
    from .routers import (
        activities,
        cred_host_notes,
        hosts,
        networks,
        pivots,
    )

    app.include_router(hosts.router)
    app.include_router(activities.router)
    app.include_router(cred_host_notes.router)
    # routers/dns.py (/api/dns, pre-infra-v2 design) was deleted 2026-08-29 —
    # it referenced a `models.DNSRecord` class that no longer existed, so
    # every request 500'd, and had no project-membership check at all
    # (security audit finding F4). DNS record management lives entirely at
    # /api/infra-v2/dns/* (routers/dns_api.py), which is what the frontend uses.
    app.include_router(pivots.router)
    app.include_router(networks.router)


def _register_credentials(app):
    from .routers import creds, encryption, secrets

    app.include_router(creds.router)
    app.include_router(secrets.router)
    app.include_router(encryption.router)


def _register_findings(app):
    from .routers import (
        checklist,
        closure,
        collections,
        findings,
        loots,
    )

    app.include_router(findings.router)
    app.include_router(loots.router)
    app.include_router(collections.router)
    app.include_router(checklist.router)
    app.include_router(closure.router)


def _register_scanning(app):
    from .routers import (
        bulk_actions,
        c2_ops_api,
        deconfliction,
        export,
        firewall_configs,
        import_export,
        import_scanners,
        jobs,
        scans,
        surface_monitor_api,
        tasks_api,
        termtrack_api,
    )
    from .routers import (
        snapshots as snapshots_router,
    )

    app.include_router(scans.router)
    app.include_router(deconfliction.router)
    app.include_router(termtrack_api.router)
    app.include_router(c2_ops_api.router)
    app.include_router(surface_monitor_api.router)
    app.include_router(jobs.router)
    app.include_router(import_scanners.router)
    app.include_router(import_export.router)
    app.include_router(export.router)
    app.include_router(snapshots_router.router)
    app.include_router(bulk_actions.router)
    app.include_router(tasks_api.router)
    app.include_router(firewall_configs.router)


def _register_c2(app):
    from .routers import attacker_exec, c2

    app.include_router(c2.router)
    app.include_router(attacker_exec.router)


def _register_automations(app):
    from .routers import (
        automations_api,
        playbooks,
        scheduled_playbooks,
    )

    app.include_router(playbooks.router)
    app.include_router(scheduled_playbooks.router)
    app.include_router(automations_api.router)


def _register_ai(app):
    from .routers import ai_v2

    app.include_router(ai_v2.router)


def _register_attack_graph(app):
    from .routers import (
        attack_graph,
        attack_path_editor,
        attack_paths,
    )

    app.include_router(attack_graph.router)
    app.include_router(attack_paths.router)
    app.include_router(attack_path_editor.router)


def _register_network(app):
    from .routers import network_map, topology

    app.include_router(network_map.router)
    app.include_router(topology.router)


def _register_infra(app):
    """The Community half of the infrastructure domain.

    Deployment — infra-v2, DNS, SSL and the managed-instance pool — moved
    to the Enterprise package and is mounted by _register_ee (see
    docs/modules/EDITIONS.md). What stays here is the workstation surface,
    whose Community half is the operator's own machines, the action log
    those machines write to, and the DevOps log, which core writes to and
    so must also be able to read.
    """
    from .routers import devops_log_api, workstations, ws_actions_api

    # ws_actions FIRST: its fixed /actions-feed path must not be swallowed
    # by the workstations router's GET /{ws_id} catch-all.
    app.include_router(ws_actions_api.router)
    app.include_router(workstations.router)
    # The DevOps log is written by core (projects, workstations, orphan
    # sweeps), so reading it is core too — see routers/devops_log_api.py.
    app.include_router(devops_log_api.router)


def _register_ee(app):
    """Routers contributed by the Enterprise package, if this is an EE build.

    A no-op in Community Edition, where ``app.ee`` is not present at all
    (docs/modules/EDITIONS.md) — the endpoints then simply do not exist and
    answer 404, which is the honest answer for a capability that is not in
    the build.
    """
    from .core.editions import ee_routers

    for router in ee_routers():
        app.include_router(router)


def _register_knowledge(app):
    from .routers import (
        import_bloodhound,
        kb,
        mitre,
        notes,
        notifications,
        report,
        search,
        sync_api,
        templates,
        timeline,
        webhooks,
    )

    app.include_router(notes.router)
    app.include_router(kb.router)
    app.include_router(mitre.router)
    app.include_router(search.router)
    app.include_router(report.router)
    app.include_router(timeline.router)
    app.include_router(templates.router)
    app.include_router(webhooks.router)
    app.include_router(notifications.router)
    app.include_router(import_bloodhound.router)
    app.include_router(sync_api.router)


_DOMAINS = [
    ("auth", _register_auth),
    ("system", _register_system),
    ("projects", _register_projects),
    ("hosts", _register_hosts),
    ("credentials", _register_credentials),
    ("findings", _register_findings),
    ("scanning", _register_scanning),
    ("c2", _register_c2),
    ("automations", _register_automations),
    ("ai", _register_ai),
    ("attack_graph", _register_attack_graph),
    ("network", _register_network),
    ("infra", _register_infra),
    ("knowledge", _register_knowledge),
    # Last on purpose: Starlette matches in registration order, so an EE
    # router extends core and can never shadow a core route. The Enterprise
    # package adds capabilities; it does not reinterpret CE behaviour.
    ("ee", _register_ee),
]


def register_all(app):
    """Register all domain routers on the FastAPI app."""
    for name, fn in _DOMAINS:
        logger.debug("Registering router domain: %s", name)
        fn(app)
    logger.info("Registered %d router domains", len(_DOMAINS))
