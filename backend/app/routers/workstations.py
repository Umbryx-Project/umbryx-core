from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, require_admin, require_infra_admin
from ..core.logging_setup import get_logger
from ..core.plan import PlanFeature, require_instance_feature
from ..core.utils import new_id, ts_now
from ..database import SessionLocal, get_db

logger = get_logger(__name__)

# Background tasks must keep a reference or CPython may garbage-collect
# them mid-run (asyncio only keeps weak refs; python:s7502).
_background_tasks: set = set()


def _spawn_tracked(coro) -> None:
    """Schedule a background task and keep a hard reference until done.

    Extracted so the tracking itself is unit-testable in CE, where the
    provisioning endpoints that call it sit behind the license gate and
    are never exercised by the Community test run.
    """
    t = asyncio.create_task(coro)
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)

router = APIRouter(prefix="/api/workstations", tags=["workstations"])

# Provisioning lives in the Enterprise package and is absent from a
# Community build (docs/modules/EDITIONS.md). This router stays in core
# because its Community half — the pool's register/bind/grant/revoke paths
# and the action log — shares helpers and a URL prefix with the
# provisioning half, and `GET /{ws_id}` would swallow the provisioning
# routes' fixed paths if they were mounted from a second router afterwards.
# So the routes exist in both editions and the *implementation* is what
# moves: in Community these handlers answer 404.
_NOT_IN_THIS_EDITION = (
    "Workstation provisioning is not part of Umbryx Community Edition. "
    "Register an existing machine over SSH instead (Workstations \u2192 Pool "
    "\u2192 Register existing)."
)


def _ee(name: str):
    """An Enterprise provisioning module, or 404 in a Community build."""
    from ..core.editions import ee_import

    mod = ee_import(f"workstation.{name}")
    if mod is None:
        raise HTTPException(404, _NOT_IN_THIS_EDITION)
    return mod


def _ee_optional(name: str):
    """Same, but None instead of 404 — for Community endpoints that merely
    have nothing to do when provisioning is absent (refreshing the status
    of a machine this build never created)."""
    from ..core.editions import ee_import

    return ee_import(f"workstation.{name}")


# Provisioning a workstation is deployment, and deployment is the paid
# asset — so the gate goes on the routes that bring a machine into
# existence, not on the router. The rest of this module is Community
# Edition: registering an existing machine over SSH (pool/register-manual),
# binding it to users and projects, granting and revoking access, probing
# it and logging every action that runs on it. Those stay open because the
# audit trail is what makes them worth having.
_requires_provisioning = Depends(
    require_instance_feature(
        PlanFeature.WORKSTATIONS,
        "Workstation provisioning is not included in your license. "
        "Umbryx Community Edition does not deploy machines — register an "
        "existing machine over SSH instead (Workstations \u2192 Pool \u2192 "
        "Register existing).",
    )
)


def _check_ws_project(ws, db, user):
    from ..core.access import is_admin

    if not is_admin(user):
        check_pid_access(db, ws.project_id, user)


def _ssh_command_from_meta(meta: dict, provider: str = "docker") -> str | None:
    if provider == "docker":
        for p in meta.get("ports") or []:
            s = str(p)
            if ":" in s:
                host_port, container_port = s.rsplit(":", 1)
                if container_port == "22":
                    return f"ssh -p {host_port} root@localhost"
            elif s == "22":
                return "ssh root@localhost"
    elif provider == "kubernetes":
        ns = meta.get("k8s_namespace", "default")
        name = meta.get("k8s_name", "")
        if name:
            return f"kubectl exec -it deploy/{name} -n {ns} -- bash"
    else:
        ip = meta.get("cloud_ip", "")
        if ip:
            return f"ssh root@{ip}"
    return None


def _ws_to_dict(ws: models.OperatorWorkstation):
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    provider = ws.provider or "docker"
    ssh_cmd = _ssh_command_from_meta(meta, provider)
    return {
        "id": ws.id,
        "project_id": ws.project_id,
        "user_id": ws.user_id,
        "template_id": ws.template_id,
        "name": ws.name,
        "provider": provider,
        "infra_provider_id": ws.infra_provider_id,
        "status": ws.status,
        "access_address": ws.access_address,
        "ssh_key_id": ws.ssh_key_id,
        "web_console_url": ws.web_console_url,
        "ssh_command": ssh_cmd,
        "created_at": ws.created_at,
        "ready_at": ws.ready_at,
        "destroyed_at": ws.destroyed_at,
        "meta": meta,
        "step": meta.get("step", ""),
    }


def _tpl_to_dict(tpl: models.WorkstationTemplate):
    return {
        "id": tpl.id,
        "name": tpl.name,
        "kind": tpl.kind,
        "category": tpl.category or "linux",
        "spec": tpl.spec,
        "is_builtin": tpl.is_builtin,
    }


@router.get("/providers")
async def providers_list():
    return {
        "providers": {
            k: {"label": v["label"], "needs_cred": v["needs_cred"]}
            for k, v in _ee("cloud_providers").WS_PROVIDERS.items()
        },
        "sizes": _ee("cloud_providers").WS_SIZES,
    }


_INFRA_PROVIDER_TYPE_ALIASES = {
    "hetzner": ("hetzner",),
    "aws": ("aws",),
    "kubernetes": ("kubernetes", "k8s", "k3s"),
}


@router.get("/infra-providers")
async def infra_providers_list(
    provider: str = "",
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """PlatformOps providers usable as the backing infra for a cloud
    workstation — id/name/type only, no credentials. Open to any
    authenticated user (unlike /infra-v2/providers, which is admin-only)
    since any project member can request a cloud workstation.
    """
    types = _INFRA_PROVIDER_TYPE_ALIASES.get(
        provider, tuple(_ee("cloud_providers").WS_PROVIDERS.keys())
    )
    rows = db.query(models.InfraProvider).order_by(models.InfraProvider.name).all()
    return [
        {"id": p.id, "name": p.name, "type": p.type}
        for p in rows
        if (p.type or "").lower() in types
    ]


@router.get("/templates")
async def templates_list(db: Session = Depends(get_db)):
    # Nothing to seed in a Community build: the builtin templates describe
    # images to provision, and this edition provisions nothing. Reads stay
    # open and simply come back empty rather than 404ing.
    provider_mod = _ee_optional("provider")
    if provider_mod is not None:
        provider_mod.seed_builtin_templates(db)
    rows = db.query(models.WorkstationTemplate).order_by(models.WorkstationTemplate.name).all()
    return [_tpl_to_dict(t) for t in rows]


@router.post("/templates", dependencies=[_requires_provisioning])
async def templates_create(
    body: dict,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    tpl = models.WorkstationTemplate(
        id=new_id("wt"),
        name=name,
        kind=body.get("kind", "docker"),
        category=body.get("category", "linux"),
        spec=body.get("spec", {}),
        is_builtin=False,
        created_at=ts_now(),
    )
    db.add(tpl)
    db.commit()
    db.refresh(tpl)
    return _tpl_to_dict(tpl)


@router.delete("/templates/{template_id}")
async def templates_delete(
    template_id: str,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    tpl = (
        db.query(models.WorkstationTemplate)
        .filter(models.WorkstationTemplate.id == template_id)
        .first()
    )
    if not tpl:
        raise HTTPException(404)
    if tpl.is_builtin:
        raise HTTPException(400, "Cannot delete builtin template")
    db.delete(tpl)
    db.commit()
    return {"ok": True}


@router.get("")
async def workstations_list(
    project_id: str = None,
    user_id: str = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from ..core.access import is_admin

    q = db.query(models.OperatorWorkstation)
    if project_id:
        if not is_admin(user):
            check_pid_access(db, project_id, user)
        q = q.filter(models.OperatorWorkstation.project_id == project_id)
    else:
        if not is_admin(user):
            pids = get_user_member_pids(db, user)
            q = q.filter(models.OperatorWorkstation.project_id.in_(pids))
    if user_id:
        q = q.filter(models.OperatorWorkstation.user_id == user_id)
    rows = q.order_by(models.OperatorWorkstation.created_at.desc()).all()
    return [_ws_to_dict(w) for w in rows]


@router.post("", dependencies=[_requires_provisioning])
async def workstations_create(
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    project_id = body.get("project_id", "").strip()
    template_id = body.get("template_id", "").strip()
    name = body.get("name", "").strip()
    provider = body.get("provider", "docker").strip()
    custom_image = body.get("custom_image", "").strip()
    registry_id = body.get("registry_id", "").strip()
    ssh_pub_key = body.get("ssh_pub_key", "").strip()
    ports_override = body.get("ports_override", [])
    replicas = body.get("replicas")
    infra_provider_id = (body.get("infra_provider_id") or "").strip()

    if not project_id or not template_id:
        raise HTTPException(400, "project_id and template_id are required")

    check_pid_access(db, project_id, user)

    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if project and project.org_id:
        from ..core.plan import PlanFeature, check_workstation_limit, has_feature

        if not has_feature(project.org_id, PlanFeature.WORKSTATIONS, db):
            raise HTTPException(402, "Workstations require the Team plan or higher.")
        want = replicas if isinstance(replicas, int) and replicas > 0 else 1
        if not check_workstation_limit(project.org_id, db, adding=want):
            raise HTTPException(
                402, "Workstation limit reached for your plan. Upgrade to create more."
            )

    ws_providers = _ee("cloud_providers").WS_PROVIDERS
    if provider not in ws_providers:
        raise HTTPException(
            400, f"Unsupported provider: {provider}. Supported: {list(ws_providers.keys())}"
        )

    if provider != "docker" and not ssh_pub_key:
        raise HTTPException(400, "SSH public key is required for cloud/kubernetes workstations")

    infra_provider = None
    if provider != "docker":
        if not infra_provider_id:
            raise HTTPException(
                400, f"infra_provider_id (PlatformOps provider) is required for {provider}"
            )
        infra_provider = (
            db.query(models.InfraProvider)
            .filter(models.InfraProvider.id == infra_provider_id)
            .first()
        )
        if not infra_provider:
            raise HTTPException(404, "PlatformOps provider not found")
        expected_type = "kubernetes" if provider == "kubernetes" else provider
        actual_type = (infra_provider.type or "").lower()
        provider_type_aliases = {"kubernetes": ("kubernetes", "k8s", "k3s")}
        if actual_type not in provider_type_aliases.get(expected_type, (expected_type,)):
            raise HTTPException(
                400,
                f"PlatformOps provider '{infra_provider.name}' is type '{actual_type}', not {provider}",
            )

    if custom_image:
        import re

        if not re.fullmatch(r"[a-zA-Z0-9._:\-/@]+", custom_image):
            raise HTTPException(
                400,
                "Invalid image reference: only alphanumerics, dots, dashes, underscores, colons, slashes and @ are allowed",
            )

    tpl = (
        db.query(models.WorkstationTemplate)
        .filter(models.WorkstationTemplate.id == template_id)
        .first()
    )
    if not tpl:
        raise HTTPException(404, "Template not found")

    if ssh_pub_key:
        import re as _re

        if not _re.match(
            r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+",
            ssh_pub_key,
        ):
            raise HTTPException(400, "Invalid SSH public key format")

    ws_meta: dict = {
        "category": tpl.category or "linux",
        "size": body.get("size", ""),
        "region": body.get("region", ""),
        "namespace": body.get("namespace", "default"),
    }
    if custom_image:
        ws_meta["custom_image"] = custom_image
    if registry_id:
        ws_meta["registry_id"] = registry_id
    if ssh_pub_key:
        ws_meta["ssh_pub_key"] = ssh_pub_key
    if ports_override and isinstance(ports_override, list):
        ws_meta["ports_override"] = [str(p) for p in ports_override if p]
    if replicas is not None:
        try:
            r = int(replicas)
            if r >= 1:
                ws_meta["replicas"] = r
        except (TypeError, ValueError):
            pass

    ws = models.OperatorWorkstation(
        id=new_id("ws"),
        project_id=project_id,
        user_id=user.id,
        template_id=template_id,
        name=name or f"ws-{user.username[:8]}-{project_id[:6]}",
        provider=provider,
        status="planned",
        meta=ws_meta,
        infra_provider_id=infra_provider.id if infra_provider else None,
        created_at=ts_now(),
    )
    db.add(ws)
    db.commit()
    db.refresh(ws)
    return _ws_to_dict(ws)


async def _ws_provision_background(ws_id: str):
    db = SessionLocal()
    try:
        ws = (
            db.query(models.OperatorWorkstation)
            .filter(models.OperatorWorkstation.id == ws_id)
            .with_for_update()
            .first()
        )
        if not ws:
            return
        try:
            await _ee("provider").provision_workstation(ws, db)
        except BaseException as e:  # noqa: BLE001 — CancelledError must not
            # escape silently either: a killed task (server shutdown) used to
            # leave the row provisioning forever, and a swallowed exception
            # left `failed` with no reason anywhere. Log the traceback AND
            # persist the reason on the row (2026-09-08 test3 incident).
            logger.exception("[ws-provision] background provisioning failed for %s", ws_id)
            ws = (
                db.query(models.OperatorWorkstation)
                .filter(models.OperatorWorkstation.id == ws_id)
                .first()
            )
            if ws:
                ws.status = "failed"
                meta = ws.meta if isinstance(ws.meta, dict) else {}
                reason = (
                    "provisioning task was cancelled (server restart?)"
                    if isinstance(e, asyncio.CancelledError)
                    else str(e)[:500]
                )
                meta["error"] = reason
                ws.meta = meta
                db.commit()
            if isinstance(e, asyncio.CancelledError):
                raise
    except Exception:
        logger.exception("[ws-provision] fatal error for %s", ws_id)
    finally:
        db.close()


async def _ws_destroy_background(ws_id: str):
    db = SessionLocal()
    try:
        ws = (
            db.query(models.OperatorWorkstation)
            .filter(models.OperatorWorkstation.id == ws_id)
            .with_for_update()
            .first()
        )
        if not ws:
            return
        try:
            await _ee("provider").destroy_workstation(ws, db)
        except BaseException as e:  # noqa: BLE001 — see provision twin above
            logger.exception("[ws-destroy] background destroy failed for %s", ws_id)
            ws = (
                db.query(models.OperatorWorkstation)
                .filter(models.OperatorWorkstation.id == ws_id)
                .first()
            )
            if ws:
                ws.status = "failed"
                meta = ws.meta if isinstance(ws.meta, dict) else {}
                reason = (
                    "destroy task was cancelled (server restart?)"
                    if isinstance(e, asyncio.CancelledError)
                    else str(e)[:500]
                )
                meta["error"] = reason
                ws.meta = meta
                db.commit()
            if isinstance(e, asyncio.CancelledError):
                raise
    except Exception:
        logger.exception("[ws-destroy] fatal error for %s", ws_id)
    finally:
        db.close()


def _check_registry_write_access(org_id: str | None, user, db: Session) -> None:
    """org_id given → caller must administer that org (or be platform_admin);
    org_id omitted → editing the platform-wide list, platform_admin only.
    Mirrors routers/image_registries.py — this router used to keep its own
    duplicate registries CRUD (writing passwords in *plaintext* straight
    into the same GlobalSetting row core.image_registries expects to
    decrypt at deploy time — a real bug, not just duplication). Delegating
    to core.image_registries here fixes that and gets org-scoping for
    free (2026-08-18)."""
    from ..core.deps import is_admin
    from ..core.org_access import require_org_admin

    if org_id:
        require_org_admin(db, org_id, user)
    elif not is_admin(user):
        raise HTTPException(403, "Admin access required")


def _check_registry_read_access(org_id: str | None, user, db: Session) -> None:
    """Mirrors routers/image_registries.py's read guard — without this, any
    authenticated user could pass an arbitrary org_id and read another
    org's registry list (URL/username; password is masked but still an
    IDOR) since this is the endpoint the frontend actually calls
    (2026-08-18)."""
    from ..core.deps import is_admin
    from ..core.org_access import get_org_role

    if org_id and not is_admin(user) and get_org_role(db, org_id, user.id) is None:
        raise HTTPException(403, "Not a member of this organization")


@router.get("/image-registries")
async def image_registries_list(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    org_id: str | None = None,
):
    from ..core.image_registries import list_image_registries

    _check_registry_read_access(org_id, user, db)
    return list_image_registries(db, org_id=org_id)


@router.post("/image-registries", dependencies=[_requires_provisioning])
async def image_registries_add(
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    org_id: str | None = None,
):
    from ..core.image_registries import add_image_registry

    _check_registry_write_access(org_id, user, db)
    name = body.get("name", "").strip()
    url = body.get("url", "").strip()
    if not name or not url:
        raise HTTPException(400, "name and url are required")
    return add_image_registry(
        name,
        url,
        body.get("username", ""),
        body.get("password", ""),
        db,
        org_id=org_id,
        is_default=body.get("is_default", False),
    )


@router.delete("/image-registries/{reg_id}")
async def image_registries_delete(
    reg_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    org_id: str | None = None,
):
    from ..core.image_registries import delete_image_registry

    _check_registry_write_access(org_id, user, db)
    if not delete_image_registry(reg_id, db, org_id=org_id):
        raise HTTPException(404)
    return {"ok": True}


@router.post("/{ws_id}/provision", dependencies=[_requires_provisioning])
async def workstations_provision(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    ws = (
        db.query(models.OperatorWorkstation)
        .filter(models.OperatorWorkstation.id == ws_id)
        .with_for_update()
        .first()
    )
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)
    if ws.status not in ("planned", "failed"):
        raise HTTPException(400, f"Cannot provision workstation in status: {ws.status}")

    # Checked here, not in the background task: provisioning runs detached
    # and returns 202 immediately, so without this a Community build would
    # accept the request, report success, and then fail out of sight —
    # leaving the machine stuck in "provisioning" with the reason only in
    # the log. Refusing up front is the honest answer.
    _ee("provider")

    # D1: an over-limit workstation (beyond the plan after a downgrade) is
    # read-only — viewable and destroyable, but not (re)provisioned.
    if ws.project_id:
        proj = db.query(models.Project).filter(models.Project.id == ws.project_id).first()
        if proj and proj.org_id:
            from ..core.plan import over_limit_workstation_ids

            if ws_id in over_limit_workstation_ids(proj.org_id, db):
                raise HTTPException(
                    402,
                    "This workstation is over your plan's limit and is read-only. "
                    "Remove another workstation or upgrade to provision it again.",
                )

    ws.status = "provisioning"
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    meta["_actor"] = user.id
    meta["_status_since"] = ts_now()
    ws.meta = meta
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(ws, "meta")
    _tl_infra(
        db,
        ws.project_id,
        user,
        "workstation",
        "deploy",
        f"Deploy started: {ws.name} ({ws.provider or 'docker'})",
    )
    db.commit()
    db.refresh(ws)

    _spawn_tracked(_ws_provision_background(ws_id))  # pragma: no cover — EE gate

    return JSONResponse(status_code=202, content=_ws_to_dict(ws))


@router.post("/{ws_id}/destroy")
async def workstations_destroy(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    ws = (
        db.query(models.OperatorWorkstation)
        .filter(models.OperatorWorkstation.id == ws_id)
        .with_for_update()
        .first()
    )
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)
    if ws.status in ("destroyed", "destroying"):
        raise HTTPException(400, f"Workstation already in status: {ws.status}")

    ws.status = "destroying"
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    meta["_actor"] = user.id
    meta["_status_since"] = ts_now()
    ws.meta = meta
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(ws, "meta")
    _tl_infra(db, ws.project_id, user, "workstation", "destroy", f"Destroy started: {ws.name}")
    db.commit()
    db.refresh(ws)

    _spawn_tracked(_ws_destroy_background(ws_id))  # pragma: no cover — EE gate

    return JSONResponse(status_code=202, content=_ws_to_dict(ws))


# ═══════════════ Pool machines & access management (2026-09-02) ═══════════════
#
# Product feature: pre-provision machines via PlatformOps InfraProviders,
# bind them to users by pushing the user's profile SSH key onto the
# machine's authorized_keys (platform key authenticates the edit), revoke
# by removing the key line. Grants/revocations land in the project
# timeline (when the machine is bound to a project) and the audit log.


def _pool_ws_out(ws: models.OperatorWorkstation, db: Session) -> dict:
    from ..core.workstation.pool import _meta

    accesses = (
        db.query(models.WorkstationAccess)
        .filter(
            models.WorkstationAccess.workstation_id == ws.id,
            models.WorkstationAccess.revoked_at.is_(None),
        )
        .all()
    )
    provider_name = ""
    if ws.infra_provider_id:
        p = (
            db.query(models.InfraProvider)
            .filter(models.InfraProvider.id == ws.infra_provider_id)
            .first()
        )
        provider_name = p.name if p else ""
    return {
        "id": ws.id,
        "name": ws.name,
        "status": ws.status,
        "provider": ws.provider,
        "infra_provider_id": ws.infra_provider_id,
        "infra_provider_name": provider_name,
        "access_address": ws.access_address,
        "project_id": ws.project_id,
        "project_name": (
            db.query(models.Project).filter(models.Project.id == ws.project_id).first().name
            if ws.project_id
            else None
        ),
        "is_pool": ws.is_pool,
        "created_at": ws.created_at,
        "ready_at": ws.ready_at,
        "meta": {k: v for k, v in _meta(ws).items() if k not in ("error", "ssh_auth")},
        "error": _meta(ws).get("error", ""),
        "ssh_auth_type": (_meta(ws).get("ssh_auth") or {}).get("type", "platform_key"),
        "executor": _meta(ws).get("executor") or {"enabled": False},
        "active_access_count": len(accesses),
        "accesses": [
            {
                "id": a.id,
                "user_id": a.user_id,
                "key_id": a.key_id,
                "granted_by": a.granted_by,
                "granted_at": a.granted_at,
            }
            for a in accesses
        ],
    }


@router.get("/pool")
def pool_list(
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """All pool machines (PlatformOps-provisioned or manually registered)."""
    rows = (
        db.query(models.OperatorWorkstation)
        .filter(models.OperatorWorkstation.is_pool.is_(True))
        .order_by(models.OperatorWorkstation.created_at.desc())
        .all()
    )
    pool_prov = _ee_optional("pool_provisioning")
    for ws in rows:
        if ws.status == "provisioning" and pool_prov is not None:
            pool_prov.refresh_pool_machine_status(ws, db)
    db.expire_all()
    return [_pool_ws_out(ws, db) for ws in rows]


@router.get("/pool/providers")
def pool_providers(
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """PlatformOps InfraProviders usable for pool provisioning."""
    types = _ee("pool_provisioning").supported_pool_provider_types()
    rows = db.query(models.InfraProvider).order_by(models.InfraProvider.name).all()
    return [
        {"id": p.id, "name": p.name, "type": p.type, "category": p.category}
        for p in rows
        if (p.type or "").lower() in types
    ]


@router.post("/pool", status_code=201, dependencies=[_requires_provisioning])
def pool_create(
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Provision a new pool machine through a PlatformOps provider."""
    provision_pool_machine = _ee("pool_provisioning").provision_pool_machine

    provider_id = (body.get("infra_provider_id") or "").strip()
    name = (body.get("name") or "").strip()
    if not provider_id or not name:
        raise HTTPException(400, "infra_provider_id and name are required")
    provider = db.query(models.InfraProvider).filter(models.InfraProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(404, "PlatformOps provider not found")

    ws = models.OperatorWorkstation(
        id=new_id("ws"),
        project_id=None,
        user_id=None,
        template_id=None,
        name=name,
        provider=(provider.type or "manual").lower(),
        status="planned",
        created_at=ts_now(),
        is_pool=True,
        infra_provider_id=provider.id,
        meta={k: body[k] for k in ("size", "image", "location", "category") if body.get(k)},
    )
    db.add(ws)
    db.commit()
    db.refresh(ws)

    provision_pool_machine(ws, db)
    db.refresh(ws)
    if body.get("make_executor") and ws.status == "ready":
        _set_executor_flag(db, ws, True, (body.get("executor_scope") or "project"))
        db.refresh(ws)
    _tl_infra(
        db,
        ws.project_id,
        user,
        "workstation",
        "provision",
        f"Pool machine provisioned: {name} → {ws.status}"
        + (f" ({ws.access_address})" if ws.access_address else ""),
    )
    db.commit()
    grants = _grant_after_create(db, user, ws, body)
    out = _pool_ws_out(ws, db)
    if grants is not None:
        out["grants"] = grants
    return out


def _grant_after_create(db, user, ws, body) -> list | None:
    """Bind the freshly created machine to a project and grant users access
    right at deploy time (assign_users: [{user_id, key_id?}] — key_id
    omitted = the user's first registered key)."""
    if not ws.is_pool:
        return None
    assign_users = body.get("assign_users") or []
    project_id = (body.get("project_id") or "").strip() or None
    if not assign_users and not project_id:
        return None
    if ws.status != "ready":
        return [
            {
                "user_id": e.get("user_id"),
                "ok": False,
                "error": f"machine not ready (status: {ws.status})",
            }
            for e in assign_users
        ]
    grants: list = []
    if project_id and project_id != ws.project_id:
        if not db.query(models.Project).filter(models.Project.id == project_id).first():
            raise HTTPException(404, "Project not found")
        ws.project_id = project_id
        db.commit()
    for entry in assign_users:
        uid = (entry.get("user_id") or "").strip()
        key_id = (entry.get("key_id") or "").strip()
        if not uid:
            grants.append({"user_id": uid, "ok": False, "error": "user_id required"})
            continue
        if not key_id:
            first_key = (
                db.query(models.UserSshKey)
                .filter(models.UserSshKey.user_id == uid)
                .order_by(models.UserSshKey.created_at)
                .first()
            )
            key_id = first_key.id if first_key else ""
        # Freshly provisioned machines are marked ready when the pod goes
        # Running, but sshd may need another second to listen — retry
        # transport-level failures for a short window.
        import time as _time

        last_err = ""
        for attempt in range(5):
            try:
                _grant_pool_access(db, user, ws.id, uid, key_id, None)
                last_err = ""
                break
            except HTTPException as exc:
                last_err = str(exc.detail)
                transportish = any(
                    w in last_err.lower()
                    for w in (
                        "refused",
                        "timed out",
                        "timeout",
                        "unreachable",
                        "reset by peer",
                        "connection closed",
                    )
                )
                if not transportish or attempt == 4:
                    break
                _time.sleep(2)
        if last_err:
            grants.append(
                {"user_id": uid, "key_id": key_id or None, "ok": False, "error": last_err}
            )
        else:
            grants.append({"user_id": uid, "key_id": key_id, "ok": True})
    db.refresh(ws)
    return grants


@router.post("/pool/{ws_id}/register-manual", status_code=201)
def pool_register_manual(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Register an EXISTING machine into the pool (idempotent per call:
    the path id is ignored; a new pool entry is created).

    Auth (optional): body.auth = {type: "platform_key"|"password"|"private_key",
    secret}. platform_key (default) — the machine already has the platform
    pubkey in authorized_keys; password/private_key — own credentials for
    arbitrary machines, stored encrypted. A connectivity probe runs at
    registration: ok → ready, failure → status "error" with the reason.
    """
    from ..core.crypto import encrypt_str
    from ..core.workstation.pool import probe_workstation

    address = (body.get("access_address") or "").strip()
    name = (body.get("name") or "").strip()
    if not address or not name:
        raise HTTPException(400, "name and access_address are required")

    auth = body.get("auth") or {}
    if not isinstance(auth, dict):
        raise HTTPException(400, "auth must be an object")
    auth_type = (auth.get("type") or "platform_key").strip()
    secret = (auth.get("secret") or "").strip()
    if auth_type not in {"platform_key", "password", "private_key"}:
        raise HTTPException(400, "auth.type must be platform_key, password or private_key")
    if auth_type != "platform_key" and not secret:
        raise HTTPException(400, "auth.secret is required for password/private_key auth")

    meta = {
        "ssh_user": body.get("ssh_user", "root"),
        "ssh_port": int(body.get("ssh_port", 22)),
        "pool_registered": True,
    }
    if auth_type != "platform_key":
        meta["ssh_auth"] = {"type": auth_type, "secret": encrypt_str(secret)}

    ws = models.OperatorWorkstation(
        id=new_id("ws"),
        project_id=None,
        user_id=None,
        template_id=None,
        name=name,
        provider=(body.get("provider") or "manual").lower(),
        status="provisioning",
        access_address=address,
        created_at=ts_now(),
        is_pool=True,
        infra_provider_id=(body.get("infra_provider_id") or "").strip() or None,
        meta=meta,
    )
    db.add(ws)
    db.commit()
    db.refresh(ws)

    try:
        probe_workstation(ws, db)
        ws.status = "ready"
        ws.ready_at = ts_now()
    except Exception as exc:  # noqa: BLE001 — record the failure, keep the entry
        ws.status = "error"
        ws.meta = {**meta, "error": f"probe failed: {exc}"}
    if body.get("make_executor"):
        _set_executor_flag(db, ws, True, (body.get("executor_scope") or "project"))
    db.commit()
    _tl_infra(
        db,
        ws.project_id,
        user,
        "workstation",
        "register",
        f"Machine registered into pool: {name} ({address})",
    )
    db.commit()
    grants = _grant_after_create(db, user, ws, body)
    out = _pool_ws_out(ws, db)
    if grants is not None:
        out["grants"] = grants
    return out


def _set_executor_flag(db, ws: models.OperatorWorkstation, enabled: bool, scope: str) -> None:
    """Set/unset the SSH-executor flag on a workstation row."""
    from sqlalchemy.orm.attributes import flag_modified

    if scope not in {"project", "all"}:
        raise HTTPException(400, "executor_scope must be 'project' or 'all'")
    meta = dict(ws.meta) if isinstance(ws.meta, dict) else {}
    if enabled:
        if ws.status != "ready":
            raise HTTPException(400, f"Machine is not ready (status: {ws.status})")
        if scope == "project" and not ws.project_id:
            raise HTTPException(
                400, "scope 'project' requires the machine to be bound to a project first"
            )
        meta["executor"] = {"enabled": True, "scope": scope}
    else:
        meta.pop("executor", None)
    ws.meta = meta
    flag_modified(ws, "meta")
    db.commit()


@router.post("/{ws_id}/executor")
def workstation_set_executor(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Make a workstation an SSH-executor machine (scans / attacker exec /
    pivots run from it). scope: 'project' — visible to the bound project,
    'all' — visible to every project."""
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404, "Workstation not found")
    enabled = bool(body.get("enabled", True))
    _set_executor_flag(db, ws, enabled, (body.get("scope") or "project"))
    _tl_infra(
        db,
        ws.project_id,
        user,
        "workstation",
        "executor" if enabled else "executor-off",
        f"SSH executor {'enabled' if enabled else 'disabled'}: {ws.name}",
    )
    db.commit()
    db.refresh(ws)
    meta = dict(ws.meta) if isinstance(ws.meta, dict) else {}
    return {"id": ws.id, "executor": meta.get("executor") or {"enabled": False}}


@router.post("/pool/{ws_id}/test")
def pool_test_machine(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Re-probe a pool machine: connectivity + credentials health.

    A successful probe also HEALS the stuck states a machine can end up
    in without the probe itself ever failing:
    - "error": the last probe failed, connectivity is back now;
    - "provisioning": register-manual was interrupted between its first
      commit and the probe (backend restart mid-request);
    - "failed": the startup reconciler marks anything still provisioning
      after a restart as failed ("Reconciled on startup") — correct for
      cloud provisioning, wrong for manual machines whose SSH is fine.
    Found live: a cyber-range SSH executor stuck this way with working
    SSH and no way to enable it — the executor flag refuses non-ready
    machines. Destroyed/destroying are never healed.
    """
    from ..core.workstation.pool import probe_workstation

    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws or not ws.is_pool:
        raise HTTPException(404, "Pool machine not found")
    try:
        probe_workstation(ws, db)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Probe failed: {exc}") from exc
    if ws.status in ("error", "provisioning", "failed"):
        meta = dict(ws.meta) if isinstance(ws.meta, dict) else {}
        meta.pop("error", None)
        ws.meta = meta
        ws.status = "ready"
        ws.ready_at = ws.ready_at or ts_now()
        db.commit()
    return {"ok": True}


@router.post("/pool/{ws_id}/refresh")
def pool_refresh(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Re-poll a provisioning pool machine (hetzner) for readiness."""
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws or not ws.is_pool:
        raise HTTPException(404, "Pool machine not found")
    pool_prov = _ee_optional("pool_provisioning")
    if ws.status == "provisioning" and pool_prov is not None:
        pool_prov.refresh_pool_machine_status(ws, db)
    db.refresh(ws)
    return _pool_ws_out(ws, db)


def _tl_infra(db, pid, user, entity, action, label, meta=None):
    """Workstation lifecycle → DevOps log (Platform Ops → DevOps tab), NOT
    the project timeline: infra ops and project activity stay separate
    streams by design (2026-09-19 review)."""
    from ..core.devops_log import log_event as devops_log_event

    devops_log_event(
        db,
        level="info",
        category=f"workstation.{action}",
        message=label,
        details={"entity": entity, "project_id": pid, **(meta or {})},
        actor=getattr(user, "username", None) or str(getattr(user, "id", "system")),
    )


def _log_access_event(db, ws, user, action: str, target_user, key_id: str, actor_name: str) -> None:
    from ..core.audit import log_action
    from ..core.events import log_event

    detail = {
        "workstation_id": ws.id,
        "workstation_name": ws.name,
        "access_address": ws.access_address,
        "target_user_id": getattr(target_user, "id", target_user),
        "target_username": getattr(target_user, "username", ""),
        "key_id": key_id,
    }
    if ws.project_id:
        log_event(
            db,
            ws.project_id,
            actor_name,
            "workstation",
            action,
            f"Workstation access {'granted to' if action == 'grant' else 'revoked from'} "
            f"{getattr(target_user, 'username', '?')} on {ws.name} ({ws.access_address})",
            detail,
        )
    log_action(
        db,
        action=f"workstation.access_{action}",
        actor_id=getattr(user, "id", None),
        actor_name=actor_name,
        target_type="workstation",
        target_id=ws.id,
        project_id=ws.project_id,
        detail=detail,
    )


@router.post("/pool/{ws_id}/assign", status_code=201)
def pool_assign(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Grant a user's SSH key access to a pool machine (multi-user).

    Optionally bind the machine to a project at the same time — grants and
    later activity then land in that project's timeline."""
    target_uid = (body.get("user_id") or "").strip()
    key_id = (body.get("key_id") or "").strip()
    project_id = (body.get("project_id") or "").strip() or None
    if not target_uid or not key_id:
        raise HTTPException(400, "user_id and key_id are required")

    _grant_pool_access(db, user, ws_id, target_uid, key_id, project_id)
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    db.refresh(ws)
    return _pool_ws_out(ws, db)


def _grant_pool_access(db, user, ws_id, target_uid, key_id, project_id):
    """Shared grant path for the assign endpoint and create-with-users
    flows. Raises HTTPException on any validation/install failure."""
    from ..core.workstation.pool import grant_access_on_machine

    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws or not ws.is_pool:
        raise HTTPException(404, "Pool machine not found")
    if ws.status != "ready":
        raise HTTPException(400, f"Machine is not ready (status: {ws.status})")

    target_user = db.query(models.User).filter(models.User.id == target_uid).first()
    if not target_user:
        raise HTTPException(404, "User not found")
    key = (
        db.query(models.UserSshKey)
        .filter(models.UserSshKey.id == key_id, models.UserSshKey.user_id == target_uid)
        .first()
    )
    if not key:
        raise HTTPException(404, "SSH key not found for this user")

    existing = (
        db.query(models.WorkstationAccess)
        .filter(
            models.WorkstationAccess.workstation_id == ws.id,
            models.WorkstationAccess.user_id == target_uid,
            models.WorkstationAccess.revoked_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(400, "User already has active access to this machine")

    if project_id and project_id != ws.project_id:
        proj = db.query(models.Project).filter(models.Project.id == project_id).first()
        if not proj:
            raise HTTPException(404, "Project not found")
        ws.project_id = project_id

    actor_name = getattr(user, "username", "") or user.id
    try:
        grant_access_on_machine(ws, db, key)
    except Exception as exc:
        db.rollback()
        raise HTTPException(502, f"Failed to install key on machine: {exc}") from exc

    access = models.WorkstationAccess(
        id=new_id("wacc"),
        workstation_id=ws.id,
        user_id=target_uid,
        key_id=key.id,
        granted_by=user.id,
        granted_at=ts_now(),
    )
    key.last_used_at = ts_now()
    db.add(access)
    db.commit()
    _log_access_event(db, ws, user, "grant", target_user, key.id, actor_name)
    db.commit()


@router.post("/pool/{ws_id}/bind")
def pool_bind_project(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Bind (or re-bind/unbind) a pool machine to a project. The machine
    then appears in that project's Access tab; grants keep landing in the
    project timeline."""
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws or not ws.is_pool:
        raise HTTPException(404, "Pool machine not found")
    project_id = (body.get("project_id") or "").strip() or None
    proj = None
    if project_id:
        proj = db.query(models.Project).filter(models.Project.id == project_id).first()
        if not proj:
            raise HTTPException(404, "Project not found")
    old = ws.project_id
    ws.project_id = project_id
    _tl_infra(
        db,
        project_id or old,
        user,
        "workstation",
        "bind" if project_id else "unbind",
        f"Machine {ws.name} "
        + (f"bound to project {proj.name}" if project_id else "unbound from project"),
        {"ws_id": ws.id, "from": old, "to": project_id},
    )
    db.commit()
    db.refresh(ws)
    return _pool_ws_out(ws, db)


@router.post("/pool/{ws_id}/revoke")
def pool_revoke(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_infra_admin),
):
    """Revoke a user's access: removes the key line from the machine and
    closes the access row. Other users on the same machine are untouched."""
    from ..core.workstation.pool import revoke_access_on_machine

    target_uid = (body.get("user_id") or "").strip()
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws or not ws.is_pool:
        raise HTTPException(404, "Pool machine not found")

    access = (
        db.query(models.WorkstationAccess)
        .filter(
            models.WorkstationAccess.workstation_id == ws.id,
            models.WorkstationAccess.user_id == target_uid,
            models.WorkstationAccess.revoked_at.is_(None),
        )
        .first()
    )
    if not access:
        raise HTTPException(404, "No active access for this user on this machine")

    target_user = db.query(models.User).filter(models.User.id == target_uid).first()
    key = db.query(models.UserSshKey).filter(models.UserSshKey.id == access.key_id).first()
    actor_name = getattr(user, "username", "") or user.id
    try:
        if key:
            revoke_access_on_machine(ws, db, key)
    except Exception as exc:
        db.rollback()
        raise HTTPException(502, f"Failed to remove key from machine: {exc}") from exc

    access.revoked_at = ts_now()
    access.revoked_by = user.id
    db.commit()
    _log_access_event(db, ws, user, "revoke", target_user, access.key_id, actor_name)
    db.commit()
    db.refresh(ws)
    return _pool_ws_out(ws, db)


@router.get("/pool/my")
def pool_my(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Machines the CURRENT user has active access to (per-user page)."""
    accesses = (
        db.query(models.WorkstationAccess)
        .filter(
            models.WorkstationAccess.user_id == user.id,
            models.WorkstationAccess.revoked_at.is_(None),
        )
        .all()
    )
    result = []
    for a in accesses:
        ws = (
            db.query(models.OperatorWorkstation)
            .filter(models.OperatorWorkstation.id == a.workstation_id)
            .first()
        )
        if not ws:
            continue
        result.append(
            {
                "access_id": a.id,
                "granted_at": a.granted_at,
                "machine": {
                    "id": ws.id,
                    "name": ws.name,
                    "access_address": ws.access_address,
                    "status": ws.status,
                    "provider": ws.provider,
                    "project_id": ws.project_id,
                },
            }
        )
    return result


@router.get("/pool/user/{uid}")
def pool_for_user(
    uid: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Admin per-user infrastructure access page: every machine the user
    holds active access to."""
    accesses = (
        db.query(models.WorkstationAccess)
        .filter(
            models.WorkstationAccess.user_id == uid,
            models.WorkstationAccess.revoked_at.is_(None),
        )
        .all()
    )
    machines = []
    for a in accesses:
        ws = (
            db.query(models.OperatorWorkstation)
            .filter(models.OperatorWorkstation.id == a.workstation_id)
            .first()
        )
        if not ws:
            continue
        machines.append(
            {
                "access_id": a.id,
                "granted_at": a.granted_at,
                "granted_by": a.granted_by,
                "machine": _pool_ws_out(ws, db),
            }
        )
    return {"user_id": uid, "machines": machines}


@router.get("/{ws_id}")
async def workstations_get(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)
    return _ws_to_dict(ws)


@router.patch("/{ws_id}")
async def workstations_update(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from sqlalchemy.orm.attributes import flag_modified

    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)

    meta = ws.meta if isinstance(ws.meta, dict) else {}
    provider = ws.provider or "docker"

    if "name" in body:
        name = body["name"].strip()
        if not name:
            raise HTTPException(400, "name cannot be empty")
        ws.name = name

    if "ports" in body:
        if provider != "docker":
            raise HTTPException(
                400,
                "Port editing is only available for Docker workstations. Cloud/K8s ports are managed by the provider.",
            )
        raw = body["ports"]
        if not isinstance(raw, list):
            raise HTTPException(400, "ports must be a list of strings")
        validated = []
        for p in raw:
            s = str(p).strip()
            if not s:
                continue
            if ":" in s:
                parts = s.rsplit(":", 1)
                if not parts[0].isdigit() or not parts[1].isdigit():
                    raise HTTPException(
                        400, f"Invalid port format '{s}'. Use hostPort:containerPort (e.g. 2222:22)"
                    )
            elif not s.isdigit():
                raise HTTPException(
                    400, f"Invalid port format '{s}'. Use hostPort:containerPort (e.g. 2222:22)"
                )
            validated.append(s)
        meta["ports_override"] = validated
        meta["ports"] = validated
        ws.meta = meta
        flag_modified(ws, "meta")

    if "custom_image" in body:
        img = body["custom_image"].strip()
        if img:
            import re

            if not re.fullmatch(r"[a-zA-Z0-9._:\-/@]+", img):
                raise HTTPException(400, "Invalid image reference")
            meta["custom_image"] = img
        else:
            meta.pop("custom_image", None)
        ws.meta = meta
        flag_modified(ws, "meta")

    if "ssh_pub_key" in body:
        key = body["ssh_pub_key"].strip()
        if key:
            import re as _re

            if not _re.match(
                r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+",
                key,
            ):
                raise HTTPException(400, "Invalid SSH public key format")
            meta["ssh_pub_key"] = key
        else:
            meta.pop("ssh_pub_key", None)
        ws.meta = meta
        flag_modified(ws, "meta")

    if "namespace" in body and provider == "kubernetes":
        ns = body["namespace"].strip()
        if ns:
            meta["namespace"] = ns
            ws.meta = meta
            flag_modified(ws, "meta")

    if "replicas" in body:
        try:
            r = int(body["replicas"])
            if r >= 1:
                meta["replicas"] = r
                ws.meta = meta
                flag_modified(ws, "meta")
        except (TypeError, ValueError):
            raise HTTPException(400, "replicas must be a positive integer")

    db.commit()
    db.refresh(ws)
    return _ws_to_dict(ws)


@router.post("/{ws_id}/restart")
async def workstations_restart(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)
    if ws.status not in ("ready", "failed"):
        raise HTTPException(400, f"Cannot restart workstation in status: {ws.status}")

    await _ee("provider").destroy_workstation(ws, db)
    db.refresh(ws)
    if ws.status not in ("destroyed", "failed"):
        raise HTTPException(500, "Destroy did not complete")
    ws.status = "planned"
    db.commit()
    db.refresh(ws)

    await _ee("provider").provision_workstation(ws, db)
    db.refresh(ws)
    return _ws_to_dict(ws)


@router.delete("/{ws_id}/force")
async def workstations_force_delete(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)

    # Audit 2026-08-31, finding 2.3.3: teardown used to swallow every
    # failure with `except Exception: pass` and then unconditionally drop
    # the DB row — a failed `docker compose down`/cloud destroy left the
    # container/VM alive with no record of it anywhere. Conservative
    # behavior (same pattern as _ws_destroy_background): if real teardown
    # fails, KEEP the row, mark it failed with the reasons, and let the
    # admin retry — never silently orphan a resource.
    provider = ws.provider or "docker"
    teardown_errors: list[str] = []

    # A Community build never created a machine, so there is nothing of ours
    # to destroy — the record points at a machine the operator owns. Checked
    # before the attempt, not caught from it: the broad `except` below would
    # otherwise file "not in this edition" as a teardown failure, keep the
    # row, and leave the admin unable to delete their own entry.
    provisioning = _ee_optional("provider")

    if provider != "docker" and provisioning is not None:
        try:
            await provisioning.destroy_workstation(ws, db)
        except Exception as e:
            teardown_errors.append(f"cloud destroy failed: {e}")
            logger.warning("[ws-force-delete] cloud destroy failed for %s: %s", ws_id, e)
    else:
        container_name = ws.meta.get("container_name") if isinstance(ws.meta, dict) else None
        if container_name:
            import asyncio
            import tempfile
            from pathlib import Path

            with tempfile.TemporaryDirectory(prefix="umbryx_ws_") as tmpdir:
                compose_file = Path(tmpdir) / "docker-compose.yml"
                compose_file.write_text("services:\n  workstation:\n    image: busybox\n")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "docker",
                        "compose",
                        "-f",
                        str(compose_file),
                        "-p",
                        container_name,
                        "down",
                        "-v",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                    if proc.returncode != 0:
                        msg = stderr.decode(errors="replace")[:200].strip() or "unknown error"
                        teardown_errors.append(
                            f"docker compose down exited {proc.returncode}: {msg}"
                        )
                        logger.warning(
                            "[ws-force-delete] docker compose down rc=%s for %s: %s",
                            proc.returncode,
                            ws_id,
                            msg,
                        )
                except Exception as e:
                    teardown_errors.append(f"docker compose down failed: {e}")
                    logger.warning(
                        "[ws-force-delete] docker compose down failed for %s: %s", ws_id, e
                    )

    if provider != "docker" and provisioning is not None:
        try:
            # This import used to be `from .cloud_credentials import ...` —
            # a module that doesn't exist. The old `except Exception: pass`
            # silently swallowed the resulting ImportError, so cloud state
            # cleanup NEVER ran (audit 2026-08-31, 2.3.3 corollary).
            _state_path = _ee("cloud_providers")._state_path

            sp = _state_path(ws.id)
            if sp and sp.exists():
                sp.unlink(missing_ok=True)
        except Exception as e:
            teardown_errors.append(f"cloud state cleanup failed: {e}")
            logger.warning("[ws-force-delete] cloud state cleanup failed for %s: %s", ws_id, e)

    if teardown_errors:
        ws.status = "failed"
        meta = ws.meta if isinstance(ws.meta, dict) else {}
        meta = dict(meta)
        meta["teardown_error"] = "; ".join(teardown_errors)[:500]
        ws.meta = meta
        db.commit()
        raise HTTPException(
            500,
            "Teardown failed — workstation record kept for retry. "
            + "; ".join(teardown_errors)[:400],
        )

    _tl_infra(
        db,
        ws.project_id,
        user,
        "workstation",
        "destroy",
        f"Force-deleted workstation: {ws.name}"
        + (f" ({ws.access_address})" if ws.access_address else ""),
    )
    db.query(models.InfraEvent).filter(models.InfraEvent.workstation_id == ws_id).delete(
        synchronize_session=False
    )
    db.delete(ws)
    db.commit()
    return {"ok": True}


@router.delete("/{ws_id}")
async def workstations_delete(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    if ws.status not in ("destroyed", "planned", "failed"):
        raise HTTPException(
            400,
            "Workstation must be destroyed/planned/failed before deletion. Use force-delete to override.",
        )
    _tl_infra(
        db,
        ws.project_id,
        user,
        "workstation",
        "destroy",
        f"Force-deleted workstation: {ws.name}"
        + (f" ({ws.access_address})" if ws.access_address else ""),
    )
    db.query(models.InfraEvent).filter(models.InfraEvent.workstation_id == ws_id).delete(
        synchronize_session=False
    )
    db.delete(ws)
    db.commit()
    return {"ok": True}


@router.post("/{ws_id}/events")
async def workstations_event(
    ws_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)
    if not ws.project_id:
        # infra_events.pid is NOT NULL — nothing to attach for an unbound
        # machine; ack without persisting instead of 500-ing
        return {"event_type": body.get("event_type", "unknown"), "stored": False}

    event = models.InfraEvent(
        id=new_id("ie"),
        project_id=ws.project_id,
        workstation_id=ws_id,
        user_id=user.id,
        event_type=body.get("event_type", "unknown"),
        payload=body.get("payload", {}),
        timestamp=ts_now(),
    )
    db.add(event)
    db.commit()
    return {"id": event.id, "event_type": event.event_type}


@router.get("/{ws_id}/events")
async def workstations_events_list(
    ws_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    _check_ws_project(ws, db, user)
    events = (
        db.query(models.InfraEvent)
        .filter(models.InfraEvent.workstation_id == ws_id)
        .order_by(models.InfraEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "payload": e.payload,
            "timestamp": e.timestamp,
        }
        for e in events
    ]
