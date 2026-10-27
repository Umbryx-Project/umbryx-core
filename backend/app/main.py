"""
Umbryx — FastAPI application entry point.

This file assembles the application from domain modules.
Business logic lives in routers/, core/, and plugins/.
"""

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.orm import Session

from .core.logging_setup import configure_logging, get_logger
from .core.utils import ts_now, utcnow

configure_logging()
logger = get_logger(__name__)

from . import models
from .core.config import COOKIE_NAME, CORS_ORIGINS, UPLOAD_ROOT
from .core.crypto import (
    encrypt_str,
    loot_value_is_sensitive,
    note_content_is_confidential,
    validate_encryption_config,
)
from .core.deps import decode_ws_token, get_current_user, is_admin, require_admin
from .core.enums import MemberRole, UserRole
from .core.key_management import encrypt_for_project, is_project_encrypted
from .core.limiter import limiter
from .core.roe_guard import ApprovalRequired, EngagementViolation
from .core.security import decode_access_token, decode_token, gen_password, hash_password
from .core.token_blacklist import is_blacklisted
from .core.utils import new_id
from .database import SessionLocal, engine, get_db
from .plugins.loader import initialize as init_plugins
from .plugins.registry import registry
from .ws import manager


# ── Schema migrations via Alembic ─────────────────────────────────────
def _run_migrations() -> None:
    """Run Alembic migrations at import time, with a DB-ready retry loop.

    The backend container can start while PostgreSQL is still in WAL
    recovery (found live on update-script deployments: the compose
    healthcheck's pg_isready passes — it only checks the socket — but
    every query gets 'FATAL: the database system is starting up').
    Migrations used to crash the process instantly, Docker restarted
    it into the same race, and jobs orphaned on every cycle. Now we
    retry for up to 60 seconds before giving up.
    """
    import time as _time
    from pathlib import Path as _Path

    from alembic.config import Config

    from alembic import command

    cfg = Config(str(_Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False))
    cfg.set_main_option("script_location", str(_Path(__file__).resolve().parent.parent / "alembic"))

    for attempt in range(30):
        try:
            command.upgrade(cfg, "head")
            break
        except Exception as exc:  # noqa: BLE001 — any DB-not-ready error
            if attempt == 29:
                raise  # 60s is enough — real failure, not a race
            msg = str(exc).lower()
            if "starting up" in msg or "connection" in msg or "refused" in msg:
                print(f"[startup] DB not ready (attempt {attempt + 1}/30): {msg[:80]}")
                _time.sleep(2)
            else:
                raise  # not a readiness issue — real migration error
    # Alembic's Config runs fileConfig() over alembic.ini, whose
    # [logger_root] level=WARN REPLACES the app's root logging (found live
    # 2026-09-08: after startup migrations the whole provisioning INFO/trace
    # output was silently swallowed — deployment failures left no logs at
    # all). configure_logging(force=True) reinstalls our handler/level.
    configure_logging()
    logger.info("Alembic migrations applied")


if os.environ.get("APP_ENV", "dev").lower() not in ("test", "testing"):
    _run_migrations()


def _fire_scheduled_playbook(sched, db, now) -> None:
    from .core.cron_utils import next_run
    from .routers.playbooks import _launch_playbook_run

    run_id = _launch_playbook_run(
        pid=sched.pid,
        playbook_id=sched.playbook_id,
        body_dict=sched.body_json or {},
        created_by="scheduler",
    )
    sched.last_run_at = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        sched.next_run_at = next_run(sched.cron_expr, after=now).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        sched.next_run_at = ""
    db.commit()
    logger.info("[scheduler] Fired schedule %s → run %s", sched.id, run_id)


# ── Scheduled playbooks background task ──────────────────────────────
def _maybe_fire_sched(sched, db, now) -> None:
    if not sched.next_run_at:
        return
    try:
        nr = datetime.strptime(sched.next_run_at, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return
    if now < nr:
        return
    # Row-level lock + re-check under the lock (F14). Atomic leader election
    # (F8) already prevents two instances from both running this loop, but
    # this is a second, independent guard — e.g. a brief overlap during
    # leader handover, or a future move to multiple scheduler workers —
    # against firing the same schedule twice in one due window. SKIP LOCKED
    # means a concurrent locker gets no row back instead of blocking, so at
    # most one caller proceeds per cycle; the other just retries next tick.
    locked = (
        db.query(models.ScheduledPlaybook)
        .filter(models.ScheduledPlaybook.id == sched.id)
        .with_for_update(skip_locked=True)
        .first()
    )
    if locked is None:
        return
    try:
        nr2 = (
            datetime.strptime(locked.next_run_at, "%Y-%m-%d %H:%M:%S")
            if locked.next_run_at
            else None
        )
    except Exception:
        nr2 = None
    if nr2 is None or now < nr2:
        db.commit()  # release the row lock; nothing to do (already fired)
        return
    _fire_scheduled_playbook(locked, db, now)


async def _scheduled_playbooks_loop():
    """Check and fire scheduled playbooks every minute."""
    await asyncio.sleep(60)  # let app fully start
    while True:
        try:
            db = SessionLocal()
            try:
                now = utcnow().replace(second=0, microsecond=0)
                scheds = (
                    db.query(models.ScheduledPlaybook)
                    .filter(models.ScheduledPlaybook.enabled)
                    .all()
                )
                for sched in scheds:
                    _maybe_fire_sched(sched, db, now)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[scheduler] loop error: %s", e)
        await asyncio.sleep(60)


async def _surface_watch_loop():
    """Start due attack-surface watches every minute.

    Shares the scheduler leader lease: watches are periodic triggers just
    like scheduled playbooks and must not double-fire in HA.
    """
    await asyncio.sleep(90)  # let app fully start (after the playbook loop)
    while True:
        try:
            from .core.surface_monitor import fire_due_watches

            db = SessionLocal()
            try:
                started = fire_due_watches(db, utcnow())
                if started:
                    logger.info("[surface-watch] started %d due watch run(s)", started)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[surface-watch] loop error: %s", e)
        await asyncio.sleep(60)


async def _ws_action_pull_loop():
    """Harvest pull-mode workstation audit logs every minute.

    Pull-mode hooks append to a local file on the machine; without this
    loop those lines only reached the platform when somebody opened the
    DevOps actions feed. Runs on every instance (idempotent offset-based
    pulls; the per-machine meta offset makes double-pulls harmless)."""
    await asyncio.sleep(75)
    while True:
        try:
            from .core.workstation.actions import harvest_pull_machines

            db = SessionLocal()
            try:
                total = harvest_pull_machines(db)
                if total:
                    logger.info("[ws-actions] pulled %d new action(s)", total)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[ws-actions] pull loop error: %s", e)
        await asyncio.sleep(60)


async def _ws_pty_harvest_loop():
    """Pull PTY recordings from pty-enabled workstations every 2 minutes
    (termtrack). Heavier than the hook pull (whole terminal bytes), so a
    slower cadence; offsets in workstation meta keep it idempotent, and
    sessions without new bytes cost one cheap listing round-trip."""
    await asyncio.sleep(150)
    while True:
        try:
            from .core.termtrack import harvest_pty
            from .core.termtrack.enrich import apply_pending_for_project
            from .models import OperatorWorkstation

            db = SessionLocal()
            try:
                pids = set()
                for ws in db.query(OperatorWorkstation).all():
                    meta = ws.meta if isinstance(ws.meta, dict) else {}
                    if not meta.get("pty_enabled"):
                        continue
                    try:
                        stats = harvest_pty(db, ws)
                        if stats.get("bytes"):
                            logger.info(
                                "[termtrack] %s: %d file(s), %d byte(s)",
                                ws.name or ws.id, stats["files"], stats["bytes"],
                            )
                        if ws.project_id:
                            pids.add(ws.project_id)
                    except Exception as exc:  # noqa: BLE001 — one machine must not stop the loop
                        logger.warning("[termtrack] harvest %s failed: %s", ws.id, exc)
                for pid in pids:
                    apply_pending_for_project(db, pid)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[termtrack] harvest loop error: %s", e)
        await asyncio.sleep(120)


def _c2_sync_is_due(cfg: dict, now) -> bool:
    interval = int(cfg.get("sync_interval_minutes") or 0)
    if interval <= 0:
        return False
    consec_failures = cfg.get("_consec_failures", 0)
    if consec_failures >= 3:
        backoff = min(interval * (2 ** (consec_failures - 3)), 1440)
        logger.debug(
            "[c2-auto-sync] %s backing off %dm after %d failures",
            cfg.get("name"),
            backoff,
            consec_failures,
        )
        interval = max(interval, backoff)
    last_sync = cfg.get("last_sync")
    if not last_sync:
        return True
    try:
        last_dt = datetime.strptime(last_sync, "%Y-%m-%d %H:%M")
        return (now - last_dt).total_seconds() / 60 >= interval
    except Exception:
        return True


_C2_SYNC_FAILURES: dict[str, int] = {}


async def _c2_sync_one_integration(cfg: dict, db, _now) -> None:
    from .routers.c2 import _do_project_sync

    project_ids = cfg.get("project_ids") or []
    if not project_ids:
        project_ids = [p.id for p in db.query(models.Project).all()]
    iid = cfg.get("id", "")
    for pid in project_ids:
        try:
            await asyncio.wait_for(
                _do_project_sync(cfg, pid, db, iid=iid, created_by="auto-sync"),
                timeout=30,
            )
            logger.info("[c2-auto-sync] %s → %s OK", cfg.get("name"), pid)
            _C2_SYNC_FAILURES.pop(iid, None)
        except TimeoutError:
            _C2_SYNC_FAILURES[iid] = _C2_SYNC_FAILURES.get(iid, 0) + 1
            logger.warning(
                "[c2-auto-sync] %s → %s timed out (failures=%d)",
                cfg.get("name"),
                pid,
                _C2_SYNC_FAILURES[iid],
            )
        except Exception as e:
            _C2_SYNC_FAILURES[iid] = _C2_SYNC_FAILURES.get(iid, 0) + 1
            logger.warning(
                "[c2-auto-sync] %s → %s failed: %s (failures=%d)",
                cfg.get("name"),
                pid,
                e,
                _C2_SYNC_FAILURES[iid],
            )


# ── C2 auto-sync background task ─────────────────────────────────────
async def _c2_auto_sync_loop():
    """Periodically sync C2 integrations that have sync_interval_minutes > 0."""
    await asyncio.sleep(30)  # initial delay to let app fully start
    while True:
        try:
            from .routers.c2 import _load_integrations

            db = SessionLocal()
            try:
                integrations = _load_integrations(db)
                now = utcnow()
                for cfg in integrations:
                    if not cfg.get("enabled") or not _c2_sync_is_due(cfg, now):
                        continue
                    await _c2_sync_one_integration(cfg, db, now)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[c2-auto-sync] loop error: %s", e)
        await asyncio.sleep(60)


# ── Automation schedule-triggered automations ─────────────────────────
async def _automations_schedule_loop():
    """Fire schedule-triggered automations (cron expressions)."""
    await asyncio.sleep(90)  # let app fully start
    while True:
        try:
            db = SessionLocal()
            try:
                from .core.automations.definition import PlaybookDefinition
                from .core.automations.engine import PlaybookEngine
                from .core.cron_utils import next_run

                now = utcnow().replace(second=0, microsecond=0)

                automations = (
                    db.query(models.PlaybookAutomation)
                    .filter(models.PlaybookAutomation.enabled.is_(True))
                    .all()
                )

                for auto in automations:
                    defn = PlaybookDefinition.from_dict(auto.definition or {})
                    for trig in defn.triggers:
                        if trig.type != "schedule" or not trig.cron:
                            continue

                        last_run = (
                            db.query(models.PlaybookRunV2)
                            .filter(
                                models.PlaybookRunV2.automation_id == auto.id,
                                models.PlaybookRunV2.trigger_type == "schedule",
                            )
                            .order_by(models.PlaybookRunV2.started_at.desc())
                            .first()
                        )

                        after = (
                            last_run.started_at
                            if last_run
                            else (auto.updated_at or auto.created_at)
                        )

                        try:
                            next_dt = next_run(trig.cron, after=after)
                        except Exception:
                            logger.warning(
                                "[pb-scheduler] invalid cron '%s' for %s", trig.cron, auto.id
                            )
                            continue

                        if next_dt <= now:
                            # Same defense-in-depth row lock as
                            # _maybe_fire_sched (F14): re-check "still due"
                            # under a row lock on the automation itself so a
                            # brief overlap between instances can't both
                            # start a run for the same trigger tick.
                            locked_auto = (
                                db.query(models.PlaybookAutomation)
                                .filter(models.PlaybookAutomation.id == auto.id)
                                .with_for_update(skip_locked=True)
                                .first()
                            )
                            if locked_auto is None:
                                continue
                            still_due_run = (
                                db.query(models.PlaybookRunV2)
                                .filter(
                                    models.PlaybookRunV2.automation_id == auto.id,
                                    models.PlaybookRunV2.trigger_type == "schedule",
                                )
                                .order_by(models.PlaybookRunV2.started_at.desc())
                                .first()
                            )
                            still_after = still_due_run.started_at if still_due_run else after
                            if still_after != after:
                                db.commit()  # another instance already fired this tick
                                continue
                            logger.info("[pb-scheduler] firing %s (cron=%s)", auto.name, trig.cron)
                            engine = PlaybookEngine(db)
                            await engine.execute(
                                automation=auto,
                                pid=auto.pid,
                                trigger_type="schedule",
                                trigger_data={"cron": trig.cron},
                                triggered_by="scheduler",
                            )
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[pb-scheduler] loop error: %s", e)
        await asyncio.sleep(60)


async def _license_heartbeat_loop():
    """Renew signed license tokens for orgs on the online channel — see
    core/license_heartbeat.py for the actual per-org logic and the grace
    period / eligibility rules (ФТ-6, docs/modules/LICENSING_TZ.md)."""
    await asyncio.sleep(60)
    while True:
        try:
            from .core.license_heartbeat import run_heartbeat_pass

            db = SessionLocal()
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, run_heartbeat_pass, db
                )
                if result:
                    logger.info("[license-heartbeat] pass complete: %s", result)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[license-heartbeat] loop error: %s", e)
        # While the instance has never been licensed it polls every 5
        # minutes (the vendor binding the c2v activates it automatically,
        # usually within minutes); once licensed, the normal 24h cadence.
        await asyncio.sleep(300 if result and "awaiting_license" in result else 86400)


async def _license_reconciliation_loop():
    """Hourly anti-tamper pass — see core/license_reconciliation.py for the
    actual per-org logic (ФТ-8, docs/modules/LICENSING_TZ.md)."""
    await asyncio.sleep(90)
    while True:
        try:
            from .core.license_reconciliation import run_reconciliation_pass

            db = SessionLocal()
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, run_reconciliation_pass, db
                )
                if result:
                    logger.info("[license-reconciliation] pass complete: %s", result)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[license-reconciliation] loop error: %s", e)
        await asyncio.sleep(3600)


async def _audit_retention_loop():
    """Daily per-tier audit trail cleanup — see core/audit_retention.py
    (ФТ-3, docs/modules/LICENSING_TZ.md)."""
    await asyncio.sleep(75)
    while True:
        try:
            from .core.audit_retention import run_retention_pass

            db = SessionLocal()
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, run_retention_pass, db
                )
                if result:
                    logger.info("[audit-retention] pass complete: %s", result)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[audit-retention] loop error: %s", e)
        await asyncio.sleep(86400)


async def _infra_health_loop():
    """Periodically health-check active workstations and stacks."""
    await asyncio.sleep(120)
    while True:
        try:
            db = SessionLocal()
            try:
                active_ws = (
                    db.query(models.OperatorWorkstation)
                    .filter(models.OperatorWorkstation.status == "ready")
                    .all()
                )
                for ws in active_ws:
                    meta = ws.meta if isinstance(ws.meta, dict) else {}
                    container = meta.get("container_name", "")
                    if not container:
                        continue
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "docker",
                            "inspect",
                            "--format",
                            "{{.State.Running}}",
                            container,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                        running = out.decode().strip().lower() == "true"
                        ws.meta = {**meta, "last_health": ts_now(), "healthy": running}
                        from sqlalchemy.orm.attributes import flag_modified as _fm

                        _fm(ws, "meta")
                        db.commit()
                    except Exception as exc:
                        logger.debug(
                            "[infra-health] workstation health check failed for %s: %s", ws.id, exc
                        )

                now = datetime.now(UTC)
                stuck_ws = (
                    db.query(models.OperatorWorkstation)
                    .filter(
                        models.OperatorWorkstation.status.in_(["provisioning", "destroying"]),
                    )
                    .all()
                )
                for ws in stuck_ws:
                    meta = ws.meta if isinstance(ws.meta, dict) else {}
                    status_since = meta.get("_status_since", "")
                    if not status_since:
                        continue
                    try:
                        since = datetime.fromisoformat(status_since)
                        if since.tzinfo is None:
                            since = since.replace(tzinfo=UTC)
                        if (now - since).total_seconds() > 15 * 60:
                            logger.warning(
                                "[watchdog] Workstation %s stuck in %s for >15min, marking failed",
                                ws.id,
                                ws.status,
                            )
                            ws.status = "failed"
                            meta["error"] = "Watchdog: operation timed out after 15 minutes"
                            ws.meta = meta
                            from sqlalchemy.orm.attributes import flag_modified

                            flag_modified(ws, "meta")
                        db.commit()
                    except Exception as exc:
                        logger.warning(
                            "[infra-health] failed to mark stuck workstation %s as failed: %s",
                            ws.id,
                            exc,
                        )
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[infra-health] loop error: %s", e)
        await asyncio.sleep(300)


async def _instance_pool_loop():
    """Periodic pool refill + health checks for managed instances."""
    await asyncio.sleep(180)
    while True:
        try:
            db = SessionLocal()
            try:
                from .core.instance_manager import refill_pool

                await asyncio.get_event_loop().run_in_executor(None, lambda: refill_pool(db))

                running = (
                    db.query(models.ManagedInstance)
                    .filter(models.ManagedInstance.status.in_(["running", "claimed"]))
                    .all()
                )
                for inst in running:
                    try:
                        from .core.k8s_client import k8s_get_deployment_status

                        k8s_status = k8s_get_deployment_status(inst.deployment_name, inst.namespace)
                        k8s_state = k8s_status.get("status", "unknown")
                        if k8s_state == "error" and inst.status != "error":
                            inst.status = "error"
                            inst.error_msg = k8s_status.get("error", "k8s deployment error")
                            db.commit()
                            logger.warning(
                                "[instance-pool] %s marked error: %s", inst.id, inst.error_msg
                            )
                        elif k8s_state == "running" and inst.status == "claimed":
                            inst.status = "running"
                            db.commit()
                    except Exception as e:
                        logger.debug("[instance-pool] health check failed for %s: %s", inst.id, e)

                provisioning = (
                    db.query(models.ManagedInstance)
                    .filter(models.ManagedInstance.status == "provisioning")
                    .all()
                )
                for inst in provisioning:
                    try:
                        from .core.k8s_client import k8s_get_deployment_status

                        k8s_status = k8s_get_deployment_status(inst.deployment_name, inst.namespace)
                        if k8s_status.get("available", 0) > 0:
                            inst.status = "standby"
                            inst.error_msg = None
                            db.commit()
                            logger.info("[instance-pool] %s provisioned → standby", inst.id)
                    except Exception as exc:
                        logger.warning(
                            "[instance-pool] k8s status check failed for %s: %s", inst.id, exc
                        )
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[instance-pool] loop error: %s", e)
        await asyncio.sleep(300)


def _run_has_awaiting_approval_job(db, run) -> bool:
    """True if any step-job of this run is held by the ROE approval gate.

    Job↔run linkage is run.jobs_json (written by _append_run_job) plus the
    job's request_json.playbook_run_id; related_entity on step jobs points
    at the project, not the run — do not use it here.
    """
    job_ids = [item.get("id") for item in (run.jobs_json or []) if item.get("id")]
    if not job_ids:
        return False
    return (
        db.query(models.Job.id)
        .filter(models.Job.id.in_(job_ids), models.Job.status == "awaiting_approval")
        .count()
        > 0
    )


def _recover_interrupted_playbook_runs(db) -> int:
    """Fail PlaybookRuns orphaned by a backend restart (audit 2026-08-31, 2.3.4).

    Runs execute as asyncio tasks inside the API process (the arq worker is
    optional and off by default). On restart those tasks vanish while the DB
    rows stay running/queued forever. At startup — before any new run can be
    launched in THIS process — every running/queued row is by definition an
    orphan, so mark it failed with an explicit reason. Child Jobs are
    recovered separately by worker_pool.startup_recovery (queued → re-queued,
    running → failed); a recovered run simply won't be updated by them anymore.

    Invariant (review follow-up, 4.1.1/4.1.2 x 2.3.4/4.1.6): a run with a
    step-job in `awaiting_approval` SURVIVES a backend restart — it waits
    for a human, it is not hung — so it is skipped here. Once the job is
    approved, jobs.approve_job re-attaches the run via
    schedule_run_resume_after_approval (the engine task itself died with the
    old process; worker_pool.startup_recovery likewise leaves
    awaiting_approval jobs untouched).
    """
    from .routers.playbooks._engine import _now, _update_run

    recovered = 0
    orphans = (
        db.query(models.PlaybookRun)
        .filter(models.PlaybookRun.status.in_(("running", "queued")))
        .all()
    )
    for run in orphans:
        if _run_has_awaiting_approval_job(db, run):
            logger.info(
                "Playbook run %s has a job awaiting ROE approval — left in place across restart",
                run.id,
            )
            continue
        _update_run(
            db,
            run,
            status="failed",
            finished_at=_now(),
            error_output="[interrupted: backend restarted while the run was in flight]",
        )
        logger.warning("Marked interrupted playbook run %s as failed", run.id)
        recovered += 1
    return recovered


def _ensure_admin_user(db) -> None:
    if db.query(models.User).count() != 0:
        return
    env_username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
    env_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    password = env_password if env_password else gen_password()
    admin = models.User(
        id=new_id("u"),
        username=env_username,
        display_name=env_username,
        password_hash=hash_password(password),
        role=UserRole.PLATFORM_ADMIN.value,
        created_at=ts_now(),
        active=True,
    )
    db.add(admin)
    db.commit()
    border = "=" * 54
    logger.info(border)
    logger.info("  Umbryx — first run")
    logger.info("  Admin account created:")
    logger.info("  Username: %s", env_username)
    if not env_password:
        pw_path = "/data/admin-password.txt"
        try:
            with open(pw_path, "w") as f:
                f.write(password)
            os.chmod(pw_path, 0o600)
        except Exception:
            pw_path = None
        logger.info("  Password: written to %s", pw_path or "(failed)")
        import sys

        print(f"Password written to {pw_path}", file=sys.stderr, flush=True)
    else:
        logger.info("  Password: (from ADMIN_PASSWORD env var)")
    logger.info(border)


def _migrate_plaintext_secrets(db) -> None:
    plaintext_creds = [
        c
        for c in db.query(models.Cred).all()
        if c.secret and not c.secret.startswith(_ENC_PREFIX) and not is_project_encrypted(c.secret)
    ]
    if plaintext_creds:
        for c in plaintext_creds:
            c.secret = encrypt_for_project(db, c.pid, c.secret)
        db.commit()
        logger.info(
            "Migrated %d plaintext credential secrets to encrypted storage", len(plaintext_creds)
        )

    plaintext_notes = [
        n
        for n in db.query(models.Note).all()
        if n.content
        and note_content_is_confidential(n.tags or [])
        and not n.content.startswith(_ENC_PREFIX)
    ]
    if plaintext_notes:
        for note in plaintext_notes:
            note.content = encrypt_str(note.content)
        db.commit()
        logger.info("Migrated %d confidential notes to encrypted storage", len(plaintext_notes))

    plaintext_loot = [
        loot
        for loot in db.query(models.Loot).all()
        if loot.value
        and loot_value_is_sensitive(
            loot.loot_type, loot.artifact_type, loot.filename, loot.storage_path, loot.public_url
        )
        and not loot.value.startswith(_ENC_PREFIX)
    ]
    if plaintext_loot:
        for loot in plaintext_loot:
            loot.value = encrypt_str(loot.value)
        db.commit()
        logger.info("Migrated %d sensitive loot values to encrypted storage", len(plaintext_loot))


def _backfill_project_owners(db) -> None:
    admin_users = (
        db.query(models.User)
        .filter(models.User.role == UserRole.PLATFORM_ADMIN.value, models.User.active)
        .all()
    )
    if not admin_users:
        return
    first_admin = admin_users[0]
    projects_without_owner = (
        db.query(models.Project)
        .filter(
            ~models.Project.id.in_(
                db.query(models.ProjectMember.project_id).filter(
                    models.ProjectMember.role == MemberRole.OWNER,
                    models.ProjectMember.is_active,
                )
            )
        )
        .all()
    )
    for project in projects_without_owner:
        existing = (
            db.query(models.ProjectMember)
            .filter(
                models.ProjectMember.project_id == project.id,
                models.ProjectMember.user_id == first_admin.id,
            )
            .first()
        )
        if existing:
            existing.role = MemberRole.OWNER
            existing.is_active = True
        else:
            db.add(
                models.ProjectMember(
                    id=new_id("pm"),
                    project_id=project.id,
                    user_id=first_admin.id,
                    role=MemberRole.OWNER,
                    created_at=datetime.now(UTC).isoformat(),
                    created_by=first_admin.id,
                    is_active=True,
                )
            )
    db.commit()


# ── Lifespan: auto-create admin on first run ──────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    _test_mode = os.environ.get("APP_ENV", "dev").lower() in ("test", "testing")

    if _test_mode:
        # Skip all DB/pool/Redis startup in test mode — tests supply their own session.
        # Extension-module routers (modules/*) still mount so their endpoints
        # are exercisable by API tests exactly as in production
        # (audit 2026-08-31, finding 4.1.5).
        try:
            from .core.modules import activate_loaded_modules, get_loader

            _ml = get_loader()
            _ml.load_all()
            activate_loaded_modules(app)
        except Exception as _mod_exc:  # pragma: no cover — loader is fail-soft
            logger.error("Extension module loading failed (test mode): %s", _mod_exc)
        yield
        return

    validate_encryption_config()

    # Route all outbound HTTP(S) egress through the configured proxy
    # (provisioners, DNS plugins, C2 integrations, kubectl subprocesses).
    try:
        from .core.outbound import apply_outbound_proxy
        from .database import SessionLocal as _SL

        _db = _SL()
        try:
            apply_outbound_proxy(_db)
        finally:
            _db.close()
    except Exception as _proxy_exc:  # pragma: no cover — non-fatal
        logger.error("outbound proxy setup failed: %s", _proxy_exc)

    db = SessionLocal()
    try:
        _ensure_admin_user(db)
        _migrate_plaintext_secrets(db)
        _backfill_project_owners(db)
        _recovered_runs = _recover_interrupted_playbook_runs(db)
        if _recovered_runs:
            logger.info("Startup recovery: %d interrupted playbook run(s) failed", _recovered_runs)
        # Stamp stacks silently detached by DB-level cascades (e.g. org
        # deletion) so the Platform Ops orphaned filter can surface them.
        try:
            from .core.infra_orphans import stamp_orphaned_stacks

            _orphans = stamp_orphaned_stacks(db)
            if _orphans:
                logger.warning(
                    "Startup sweep: %d stack(s) found orphaned (project row "
                    "deleted without stack teardown) — marked for review",
                    _orphans,
                )
        except Exception as _orphan_exc:  # pragma: no cover — sweep is fail-soft
            logger.error("Orphaned-stack sweep failed: %s", _orphan_exc)

        # Builtin global KB content (operations guides; MITRE reference) —
        # idempotent by marker tags, re-runs are cheap no-ops. Fail-soft:
        # a seeding problem must never block startup.
        try:
            from .routers.kb import _seed_kb_guides, _seed_kb_mitre

            class _Sys:
                username = "system"

            _guides = _seed_kb_guides(db, _Sys())
            _mitre = _seed_kb_mitre(db, _Sys())
            if _guides["created"] or _mitre["created"]:
                logger.info(
                    "KB seed: %d guide(s), %d MITRE article(s) created",
                    _guides["created"], _mitre["created"],
                )
        except Exception as _kb_exc:  # pragma: no cover — seed is fail-soft
            logger.error("KB builtin seeding failed: %s", _kb_exc)
    finally:
        db.close()

    init_plugins(app)

    # ── Load extension modules from /modules/ ──────────────────────────
    from .core.modules import activate_loaded_modules, get_loader

    try:
        _mod_loader = get_loader()
        _mod_loader.load_all()
        activate_loaded_modules(app)
        _ext_count = sum(1 for m in _mod_loader.enabled())
        logger.info("Extension modules: %d loaded, %d enabled", len(_mod_loader.all()), _ext_count)
    except Exception as _mod_exc:
        logger.error("Extension module loading failed: %s", _mod_exc)

    # ── arq pool (when WORKER_BACKEND=arq) ──────────────────────────────
    _arq_pool = None
    if os.environ.get("WORKER_BACKEND", "internal").lower() == "arq":
        try:
            from arq import create_pool as _arq_create_pool

            from .core.arq_pool import set_arq_pool
            from .core.arq_worker import _redis_settings_from_url

            _arq_pool = await _arq_create_pool(_redis_settings_from_url())
            set_arq_pool(_arq_pool)
            logger.info("arq Redis pool initialised (WORKER_BACKEND=arq)")
        except Exception as _arq_exc:
            logger.error(
                "Failed to initialise arq pool: %s — falling back to internal worker", _arq_exc
            )

    # Start worker pool + recovery
    from .core.worker_pool import get_pool, startup_recovery

    pool = get_pool()
    pool.start()
    recovery_db = SessionLocal()
    try:
        recovered = startup_recovery(recovery_db)
        if recovered:
            import logging

            logging.getLogger(__name__).info("Recovered %d queued jobs on startup", recovered)
    finally:
        recovery_db.close()

    _startup_db = SessionLocal()
    try:
        from .core.system_log import log_system

        log_system(
            _startup_db, "platform.started", {"version": "0.3.0"}, message="Umbryx platform started"
        )
    except Exception as exc:
        logger.debug("Failed to log platform.started event: %s", exc)
    finally:
        _startup_db.close()

    _reconcile_db = SessionLocal()
    try:
        _stuck_ws = (
            _reconcile_db.query(models.OperatorWorkstation)
            .filter(
                models.OperatorWorkstation.status.in_(["provisioning", "destroying"]),
            )
            .all()
        )
        for _ws in _stuck_ws:
            _old = _ws.status
            _ws.status = "failed"
            _meta = _ws.meta if isinstance(_ws.meta, dict) else {}
            _meta["error"] = f"Reconciled on startup (was {_old})"
            _ws.meta = _meta
            from sqlalchemy.orm.attributes import flag_modified

            flag_modified(_ws, "meta")
            logger.warning("Reconciled stuck workstation %s: %s → failed", _ws.id, _old)
        if _stuck_ws:
            _reconcile_db.commit()
    except Exception as _rec_exc:
        logger.error("Reconciliation error: %s", _rec_exc)
    finally:
        _reconcile_db.close()

    # Start Redis pub/sub for WebSocket broadcast
    await manager.startup()

    # Store main event loop for thread-safe broadcasts (infra background tasks)
    from .core.events import set_main_loop

    set_main_loop(asyncio.get_running_loop())

    from .core.leader_election import acquire_lease, get_redis_client, release_lease, renewal_loop

    _leader_redis = get_redis_client()

    task_renewal_c2 = task_renewal_sched = task_renewal_health = task_renewal_pool = (
        task_renewal_pb
    ) = task_renewal_license = task_renewal_license_recon = task_renewal_audit_retention = None

    c2_leader = await acquire_lease("c2_sync", _leader_redis)
    if c2_leader:
        task_c2 = asyncio.create_task(_c2_auto_sync_loop())
        task_renewal_c2 = asyncio.create_task(
            renewal_loop("c2_sync", _leader_redis, on_lost=task_c2.cancel)
        )
    else:
        task_c2 = asyncio.create_task(asyncio.sleep(0))

    sched_leader = await acquire_lease("scheduler", _leader_redis)
    if sched_leader:
        task_scheduler = asyncio.create_task(_scheduled_playbooks_loop())
        task_watch = asyncio.create_task(_surface_watch_loop())
        task_ws_pull = asyncio.create_task(_ws_action_pull_loop())
        task_pty_pull = asyncio.create_task(_ws_pty_harvest_loop())
        task_renewal_sched = asyncio.create_task(
            renewal_loop("scheduler", _leader_redis, on_lost=lambda: (task_scheduler.cancel(), task_watch.cancel(), task_ws_pull.cancel(), task_pty_pull.cancel()))
        )
    else:
        task_scheduler = asyncio.create_task(asyncio.sleep(0))
        task_watch = asyncio.create_task(asyncio.sleep(0))
        task_ws_pull = asyncio.create_task(asyncio.sleep(0))
        task_pty_pull = asyncio.create_task(asyncio.sleep(0))

    health_leader = await acquire_lease("infra_health", _leader_redis)
    if health_leader:
        task_health = asyncio.create_task(_infra_health_loop())
        task_renewal_health = asyncio.create_task(
            renewal_loop("infra_health", _leader_redis, on_lost=task_health.cancel)
        )
    else:
        task_health = asyncio.create_task(asyncio.sleep(0))

    pool_leader = await acquire_lease("instance_pool", _leader_redis)
    if pool_leader:
        task_pool = asyncio.create_task(_instance_pool_loop())
        task_renewal_pool = asyncio.create_task(
            renewal_loop("instance_pool", _leader_redis, on_lost=task_pool.cancel)
        )
    else:
        task_pool = asyncio.create_task(asyncio.sleep(0))

    pb_sched_leader = await acquire_lease("pb_scheduler", _leader_redis)
    if pb_sched_leader:
        task_pb_sched = asyncio.create_task(_automations_schedule_loop())
        task_renewal_pb = asyncio.create_task(
            renewal_loop("pb_scheduler", _leader_redis, on_lost=task_pb_sched.cancel)
        )
    else:
        task_pb_sched = asyncio.create_task(asyncio.sleep(0))

    license_leader = await acquire_lease("license_heartbeat", _leader_redis)
    if license_leader:
        task_license = asyncio.create_task(_license_heartbeat_loop())
        task_renewal_license = asyncio.create_task(
            renewal_loop("license_heartbeat", _leader_redis, on_lost=task_license.cancel)
        )
    else:
        task_license = asyncio.create_task(asyncio.sleep(0))

    license_recon_leader = await acquire_lease("license_reconciliation", _leader_redis)
    if license_recon_leader:
        task_license_recon = asyncio.create_task(_license_reconciliation_loop())
        task_renewal_license_recon = asyncio.create_task(
            renewal_loop("license_reconciliation", _leader_redis, on_lost=task_license_recon.cancel)
        )
    else:
        task_license_recon = asyncio.create_task(asyncio.sleep(0))

    audit_retention_leader = await acquire_lease("audit_retention", _leader_redis)
    if audit_retention_leader:
        task_audit_retention = asyncio.create_task(_audit_retention_loop())
        task_renewal_audit_retention = asyncio.create_task(
            renewal_loop("audit_retention", _leader_redis, on_lost=task_audit_retention.cancel)
        )
    else:
        task_audit_retention = asyncio.create_task(asyncio.sleep(0))

    yield

    for t in [
        task_renewal_c2,
        task_renewal_sched,
        task_renewal_health,
        task_renewal_pool,
        task_renewal_pb,
        task_renewal_license,
        task_renewal_license_recon,
        task_renewal_audit_retention,
    ]:
        if t:
            t.cancel()
    for role in [
        "c2_sync",
        "scheduler",
        "infra_health",
        "instance_pool",
        "pb_scheduler",
        "license_heartbeat",
        "license_reconciliation",
        "audit_retention",
    ]:
        await release_lease(role, _leader_redis)

    task_c2.cancel()
    task_scheduler.cancel()
    task_health.cancel()
    task_pool.cancel()
    task_pb_sched.cancel()
    task_license.cancel()
    task_license_recon.cancel()
    task_audit_retention.cancel()
    await pool.stop()
    if _arq_pool is not None:
        await _arq_pool.close()
        logger.info("arq Redis pool closed")
    await manager.shutdown()
    _all_tasks = [
        task_c2,
        task_scheduler,
        task_watch,
        task_ws_pull,
        task_pty_pull,
        task_health,
        task_pool,
        task_pb_sched,
        task_license,
        task_license_recon,
        task_audit_retention,
    ]
    for t in [
        task_renewal_c2,
        task_renewal_sched,
        task_renewal_health,
        task_renewal_pool,
        task_renewal_pb,
        task_renewal_license,
        task_renewal_license_recon,
        task_renewal_audit_retention,
    ]:
        if t:
            _all_tasks.append(t)
    await asyncio.gather(*_all_tasks, return_exceptions=True)


# ── FastAPI app ───────────────────────────────────────────────────────
_ENC_PREFIX = "__enc__:"
_BEARER_PREFIX = "Bearer "


def _iter_file(safe, start: int, end: int, chunk: int = 1024 * 1024):
    with open(safe, "rb") as f:
        f.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            data = f.read(min(chunk, remaining))
            if not data:
                break
            remaining -= len(data)
            yield data


def _parse_range_header(header: str, file_size: int) -> tuple[int, int] | None:
    """Return (start, end) for a valid Range header, or None for 416."""
    try:
        byte_range = header.replace("bytes=", "").strip()
        start_str, end_str = byte_range.split("-")
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else file_size - 1
        end = min(end, file_size - 1)
    except Exception:
        return None
    if start > end or start >= file_size:
        return None
    return start, end


def _resolve_loot_meta(db, pid: str, disk_name: str, entity: str) -> tuple:
    """Return (loot_rec, content_type, orig_filename) for a download."""
    import mimetypes

    loot_rec = None
    orig_filename = disk_name
    content_type = None
    if entity == "loot":
        loot_rec = (
            db.query(models.Loot)
            # Security audit 2026-10-09 (LOW): a "%" or "_" in the URL filename
            # acted as a LIKE wildcard and could match a foreign loot row's
            # metadata. Escape both, keeping the literal meaning.
            .filter(
                models.Loot.pid == pid,
                models.Loot.storage_path.like(
                    f"%{disk_name.replace('%', chr(92) + '%').replace('_', chr(92) + '_')}",
                    escape=chr(92),
                ),
            )
            .first()
        )
        if loot_rec:
            content_type = loot_rec.content_type or None
            orig_filename = loot_rec.filename or disk_name
    if not content_type:
        content_type = mimetypes.guess_type(orig_filename)[0] or "application/octet-stream"
    return loot_rec, content_type, orig_filename


async def _handle_ws_message(ws: WebSocket, pid: str, msg: dict) -> None:
    if msg.get("type") == "ping":
        await manager.touch_presence(ws)
        await ws.send_text('{"type":"pong"}')
        return
    if msg.get("type") == "focus":
        await manager.set_focus(ws, msg.get("note_id"))
    elif msg.get("type") == "blur":
        await manager.set_focus(ws, None)
    elif msg.get("type") == "view":
        await manager.set_view(ws, msg.get("view"))
    elif msg.get("type") == "unview":
        await manager.set_view(ws, None)
    await manager.broadcast_presence(pid)


# /docs, /openapi.json and /redoc are mounted by FastAPI on the app root,
# outside the /api/ prefix our auth middleware gates — so unlike every real
# endpoint they were reachable with no token at all, handing an unauthenticated
# caller the full 447-endpoint API surface (security test, 2026-09-02,
# finding 1). APP_ENV alone isn't a safe gate for this: the deployed test
# stand also runs with the "dev" default, not "production" — so disable by
# default everywhere and require an explicit opt-in for local development.
_docs_enabled = os.environ.get("ENABLE_API_DOCS", "false").strip().lower() in (
    "1",
    "true",
    "yes",
)
from .core.license_gate import LicenseGateMiddleware

app = FastAPI(
    title="Umbryx API",
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
)

from starlette.middleware.base import BaseHTTPMiddleware

# Added first so it sits innermost — runs after _ApiVersionMiddleware has
# rewritten /api/v1/ paths to /api/, so the gate classifies the real path.
app.add_middleware(LicenseGateMiddleware)


class _ApiVersionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.scope["path"]
        if path.startswith("/api/v1/"):
            request.scope["path"] = path.replace("/api/v1/", "/api/", 1)
            request.scope["raw_path"] = request.scope["path"].encode()
        return await call_next(request)


app.add_middleware(_ApiVersionMiddleware)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-XSS-Protection", "0")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
        )
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return resp


app.add_middleware(_SecurityHeadersMiddleware)
# Authenticated file downloads — replaces the unauthenticated StaticFiles mount.
# Token can be passed as ?token= query param for <a href> download links.

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(EngagementViolation)
async def _engagement_violation_handler(request: Request, exc: EngagementViolation):
    payload: dict = {"detail": str(exc), "code": "roe_violation"}
    out_of_scope = getattr(exc, "out_of_scope", None)
    if out_of_scope:
        payload["out_of_scope"] = out_of_scope
    return JSONResponse(payload, status_code=403)


@app.exception_handler(ApprovalRequired)
async def _approval_required_handler(request: Request, exc: ApprovalRequired):
    # The job exists and is held in awaiting_approval — tell the caller
    # that explicitly instead of a bare error.
    return JSONResponse(
        {
            "detail": str(exc),
            "code": "roe_approval_required",
            "activities": exc.activities,
            "job_status": "awaiting_approval",
        },
        status_code=202,
    )


# Gzip JSON responses ≥1KB. Hosts/jobs/timeline list endpoints often
# return tens of KB of repetitive JSON keys — typical compression
# ratio is 5-10x. minimum_size avoids overhead on tiny payloads.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Unified error contract: every error response is {code, message, details?, detail}
from .core.errors import install_error_handlers  # noqa: E402

install_error_handlers(app)

# ── Auth middleware ───────────────────────────────────────────────────
_PUBLIC_PATHS = (
    "/api/auth/login",
    # Workstation shell-hook ingest: authenticated by the per-workstation
    # bearer token inside the endpoint itself (workstations have no user
    # cookies and must ever get any).
    "/api/workstations/ws-actions/",
    "/api/auth/setup",
    "/api/auth/status",
    # Authenticates with the refresh_token in its own body (validated
    # inside: signature, type=refresh, blacklist, active user) — same model
    # as /login. Was blocked here while no client could ever obtain a
    # refresh token, making the endpoint dead code.
    "/api/auth/refresh",
    "/api/auth/mfa/verify",
    # The whole point of OIDC login is authenticating someone who doesn't
    # have a session yet — /login, /callback, /providers, /confirm-link
    # all have to be reachable pre-auth or the flow can never start. Each
    # endpoint does its own validation (state+PKCE+nonce, JWKS signature,
    # password-verified account linking) rather than relying on this
    # middleware for anything.
    "/api/auth/oidc/",
    "/api/webhooks/",
    "/api/health",
    "/api/infra-v2/services/heartbeat",
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.middleware("http")
async def slow_request_middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = int((time.monotonic() - start) * 1000)
    if duration_ms > 500:
        try:
            db = SessionLocal()
            from .core.system_log import log_performance

            log_performance(db, request.url.path, duration_ms)
        except Exception as exc:
            logger.debug("Failed to log slow request performance: %s", exc)
        finally:
            db.close()
    return response


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path.startswith(_PUBLIC_PATHS):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    # Cookie auth (httpOnly, set by /api/auth/login)
    if not auth.startswith(_BEARER_PREFIX):
        cookie_token = request.cookies.get(COOKIE_NAME, "")
        if cookie_token:
            auth = f"Bearer {cookie_token}"
    # SSE/EventSource can't set headers — allow short-lived stream token via query param.
    # Security audit 2026-10-09 (M-3): the token used to be accepted on ANY
    # /api path and method — a leaked 120s URL granted full API access. Bind
    # stream tokens to the two streaming endpoints they exist for, and apply
    # the same global-viewer write block the cookie/bearer branch applies.
    if not auth.startswith(_BEARER_PREFIX):
        qs_token = request.query_params.get("token", "")
        if qs_token:
            payload = decode_token(qs_token)
            if payload and payload.get("type") == "stream":
                import re as _re
                import time

                _STREAM_ROUTES = (
                    (_re.compile(r"^/api/projects/[^/]+/jobs/[^/]+/output-stream$"), ("GET",)),
                    (_re.compile(r"^/api/projects/[^/]+/ai/chats/[^/]+/stream$"), ("GET", "POST")),
                )
                if not any(rx.match(path) and request.method in methods for rx, methods in _STREAM_ROUTES):
                    return JSONResponse(
                        {"detail": "Stream tokens are only valid on streaming endpoints"},
                        status_code=401,
                    )
                if time.time() - payload.get("iat", 0) > 120:
                    return JSONResponse({"detail": "Stream token expired"}, status_code=401)
                if await is_blacklisted(payload.get("jti", "")):
                    return JSONResponse({"detail": "Stream token revoked"}, status_code=401)
                request.state.uid = payload["sub"]
                request.state.username = payload.get("username", "")
                request.state.role = payload.get("role", "user")
                request.state.jti = payload.get("jti", "")
                if request.state.role == UserRole.VIEWER and request.method not in ("GET", "HEAD", "OPTIONS"):
                    return JSONResponse({"detail": "Read-only account"}, status_code=403)
                return await call_next(request)
            auth = f"Bearer {qs_token}"
    if not auth.startswith(_BEARER_PREFIX):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    payload = decode_access_token(auth[7:])
    if not payload:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)
    if await is_blacklisted(payload.get("jti", "")):
        return JSONResponse({"detail": "Token has been revoked"}, status_code=401)
    request.state.uid = payload["sub"]
    request.state.username = payload.get("username", "")
    request.state.role = payload.get("role", "user")
    if request.state.role == UserRole.VIEWER and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse({"detail": "Read-only account"}, status_code=403)
    return await call_next(request)


# CORSMiddleware must be added last so it becomes the outermost layer,
# handling OPTIONS preflight before auth_middleware can reject it.
#
# Security test 2026-09-02, finding 4: an empty CORS_ORIGINS used to fall
# back to allow_origins=["*"] — a wildcard on every preflight for any
# origin. The default is now SAME-ORIGIN: no CORSMiddleware is mounted at
# all (the SPA is served from the same origin, and the Vite dev server
# proxies /api same-origin too). Cross-origin deployments must list their
# origins in CORS_ORIGINS explicitly (see .env.example).
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )


# ── Authenticated file downloads ─────────────────────────────────────


async def _authenticate_download_request(
    request: Request, db: Session
) -> tuple["models.User | None", "JSONResponse | None"]:
    # Same precedence as auth_middleware (header > cookie > query token).
    # This used to check only Authorization/?token=, but login only ever
    # sets the httpOnly cookie — no access_token is returned to the client
    # to put in a header, and /api/auth/refresh needs a refresh_token that
    # is likewise never issued. The frontend's downloadUrl() has always
    # assumed "cookie auth handles authentication for download links"
    # (frontend/src/api/index.ts) — every download link 401'd for every
    # real user (security retest, 2026-09-03).
    token = request.headers.get("Authorization", "")
    if not token.startswith(_BEARER_PREFIX):
        cookie_token = request.cookies.get(COOKIE_NAME, "")
        if cookie_token:
            token = f"Bearer {cookie_token}"
    if not token.startswith(_BEARER_PREFIX):
        qs = request.query_params.get("token", "")
        if qs:
            token = f"Bearer {qs}"
    if not token.startswith(_BEARER_PREFIX):
        return None, JSONResponse({"detail": "Not authenticated"}, status_code=401)
    user_payload = decode_access_token(token[7:])
    if not user_payload:
        return None, JSONResponse({"detail": "Invalid or expired token"}, status_code=401)
    if await is_blacklisted(user_payload.get("jti", "")):
        return None, JSONResponse({"detail": "Token has been revoked"}, status_code=401)
    user = db.query(models.User).filter(models.User.id == user_payload["sub"]).first()
    if not user or not user.active:
        return None, JSONResponse({"detail": "User not found"}, status_code=401)
    return user, None


def _serve_encrypted_loot_file(loot_rec, safe, content_type: str, disposition: str):
    if not (loot_rec and getattr(loot_rec, "file_encrypted", False)):
        return None
    from cryptography.fernet import InvalidToken
    from fastapi.responses import Response

    from .core.crypto import decrypt_bytes as _decrypt_bytes

    try:
        decrypted = _decrypt_bytes(safe.read_bytes())
    except (InvalidToken, Exception) as _exc:
        logger.error("Failed to decrypt loot file %s: %s", safe, _exc)
        return JSONResponse({"detail": "File decryption failed"}, status_code=500)
    return Response(
        content=decrypted,
        status_code=200,
        media_type=content_type,
        headers={"Content-Disposition": disposition, "Content-Length": str(len(decrypted))},
    )


def _serve_upload_range_response(
    safe, range_header: str, file_size: int, content_type: str, disposition: str
):
    from fastapi.responses import Response
    from fastapi.responses import StreamingResponse as _SR

    parsed = _parse_range_header(range_header, file_size)
    if parsed is None:
        return Response(status_code=416, headers={"Content-Range": f"bytes */{file_size}"})
    start, end = parsed
    return _SR(
        _iter_file(safe, start, end),
        status_code=206,
        media_type=content_type,
        headers={
            "Content-Disposition": disposition,
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(end - start + 1),
            "Accept-Ranges": "bytes",
        },
    )


@app.get("/api/uploads/{pid}/{path:path}")
async def download_upload(
    pid: str,
    path: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    user, err = await _authenticate_download_request(request, db)
    if err:
        return err

    from pathlib import Path as _Path
    from pathlib import PurePosixPath as _PurePosixPath

    from .core.access import check_pid_access as _check
    from .core.events import log_event as _log_event

    # Security audit 2026-10-07 (finding 1): normalize the path BEFORE it
    # drives permission selection, the storage key and the filesystem
    # fallback. Previously "x/../loot/f" was authorized as a note attachment
    # (notes.read) but served and decrypted as loot, and
    # "../<other-pid>/loot/f" crossed into another project's upload tree.
    if not path or path.startswith("/") or "\\" in path:
        return JSONResponse({"detail": "Invalid path"}, status_code=400)
    _parts = _PurePosixPath(path).parts
    if ".." in _parts:
        return JSONResponse({"detail": "Invalid path"}, status_code=400)
    path = "/".join(_parts)
    if not path:
        return JSONResponse({"detail": "Invalid path"}, status_code=400)

    try:
        entity = "loot" if path.startswith("loot/") else "note_attachment"
        permission = "loot.read" if entity == "loot" else "notes.read"
        _check(db, pid, user, permission)
    except Exception:
        return JSONResponse({"detail": "Access denied"}, status_code=403)

    from .core.storage import get_storage_backend

    _storage = get_storage_backend()
    _key = f"{pid}/{path}"
    file_data = await _storage.load(_key)

    if file_data is None:
        from .core.utils import ensure_under_upload_root

        target = UPLOAD_ROOT / pid / path
        try:
            safe = ensure_under_upload_root(target)
        except Exception:
            return JSONResponse({"detail": "Invalid path"}, status_code=400)

        if not safe.exists() or not safe.is_file():
            return JSONResponse({"detail": "File not found"}, status_code=404)
        file_data = safe.read_bytes()

    _log_event(
        db,
        pid,
        getattr(user, "username", None),
        "audit",
        "download_sensitive_file",
        f"Downloaded {entity}: {_Path(path).name}",
        {"path": path, "entity": entity},
    )
    db.commit()

    loot_rec, content_type, orig_filename = _resolve_loot_meta(db, pid, _Path(path).name, entity)
    # Serve inline (so the in-app previewer can render it, e.g. a PDF in an
    # <iframe>) only when the caller asks for it AND the type is safe to render
    # in the browser. HTML/SVG/XML are always forced to download — inline they
    # could execute script in our origin. Everything else defaults to
    # attachment (the Download button's behaviour, unchanged).
    _ct = (content_type or "").lower()
    _INLINE_SAFE = _ct == "application/pdf" or _ct.startswith(("image/", "text/plain", "audio/", "video/"))
    _INLINE_BLOCKED = _ct in ("image/svg+xml", "text/html", "application/xhtml+xml", "application/xml", "text/xml")
    _want_inline = request.query_params.get("disposition") == "inline"
    _disp_type = "inline" if (_want_inline and _INLINE_SAFE and not _INLINE_BLOCKED) else "attachment"
    disposition = f'{_disp_type}; filename="{orig_filename}"'

    if loot_rec and getattr(loot_rec, "file_encrypted", False):
        from cryptography.fernet import InvalidToken
        from fastapi.responses import Response

        from .core.crypto import decrypt_bytes as _decrypt_bytes

        try:
            decrypted = _decrypt_bytes(file_data)
        except (InvalidToken, Exception) as _exc:
            logger.error("Failed to decrypt loot file %s: %s", _key, _exc)
            return JSONResponse({"detail": "File decryption failed"}, status_code=500)
        return Response(
            content=decrypted,
            status_code=200,
            media_type=content_type,
            headers={"Content-Disposition": disposition, "Content-Length": str(len(decrypted))},
        )

    from fastapi.responses import Response

    file_size = len(file_data)
    range_header = request.headers.get("Range")
    if range_header:
        parsed = _parse_range_header(range_header, file_size)
        if parsed is None:
            return Response(status_code=416, headers={"Content-Range": f"bytes */{file_size}"})
        start, end = parsed
        return Response(
            content=file_data[start : end + 1],
            status_code=206,
            media_type=content_type,
            headers={
                "Content-Disposition": disposition,
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Content-Length": str(end - start + 1),
                "Accept-Ranges": "bytes",
            },
        )

    return Response(
        content=file_data,
        status_code=200,
        media_type=content_type,
        headers={
            "Content-Disposition": disposition,
            "Content-Length": str(file_size),
            "Accept-Ranges": "bytes",
        },
    )


# ── WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws/{pid}")
async def websocket_endpoint(
    ws: WebSocket,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
):
    # Security audit 2026-10-07 (M1): cookie-only auth. The former ?token=
    # query parameter leaked JWTs into proxy access logs/referrers — the
    # first-party frontend never used it (useSync.js connects with the
    # session cookie). Revoked tokens are also rejected now (blacklist
    # check used to be REST-only, so a logged-out token kept working over
    # WS until expiry).
    effective_token = ws.cookies.get(COOKIE_NAME, "")
    user = decode_ws_token(effective_token, db)
    if not user:
        await ws.close(code=4001)
        return
    from .core.security import decode_access_token

    _ws_payload = decode_access_token(effective_token)
    if _ws_payload and await is_blacklisted(_ws_payload.get("jti", "")):
        await ws.close(code=4001)
        return

    is_global_admin = is_admin(user)

    # Organization rooms reuse this same endpoint/ConnectionManager — the
    # room key is just an opaque string to `manager`, so `org:<org_id>`
    # rides the identical broadcast/reconnect/presence machinery real
    # project rooms use, rather than a parallel realtime mechanism
    # (2026-08-18: org member add/remove/role-change previously required a
    # manual page reload to see, since nothing emitted a WS event and the
    # frontend had no channel to receive one on while no project was
    # selected).
    if pid.startswith("org:"):
        org_id = pid[len("org:") :]
        from .core.org_access import get_org_role

        if not is_global_admin and get_org_role(db, org_id, user.id) is None:
            await ws.close(code=4003)
            return
        permissions: frozenset[str] = frozenset()
    else:
        from .core.permissions import get_membership, get_permissions_for_role

        if is_global_admin:
            # Global admins effectively have every project-level permission
            permissions = frozenset()
        else:
            membership = get_membership(db, pid, user.id)
            if not membership:
                await ws.close(code=4003)
                return
            permissions = frozenset(get_permissions_for_role(membership.role))
    connected = await manager.connect(
        ws,
        pid,
        user.username,
        permissions=permissions,
        is_global_admin=is_global_admin,
        user_id=user.id,
    )
    if not connected:
        return
    await manager.broadcast_presence(pid)
    try:
        while True:
            raw = await ws.receive_text()
            if not manager.allow_message(ws):
                continue
            try:
                await _handle_ws_message(ws, pid, json.loads(raw))
            except Exception as e:
                logger.warning("WebSocket message parse error for pid=%s: %s", pid, e)
    except WebSocketDisconnect:
        await manager.disconnect(ws, pid)
        await manager.broadcast_presence(pid)


# ── Health & presence ─────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    from .database import engine

    checks = {}

    try:
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["db"] = "ok"
    except Exception:
        checks["db"] = "error"

    try:
        from .core.redis_factory import create_redis_connection

        r = create_redis_connection()
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "error"

    ok = all(v == "ok" for v in checks.values())
    if ok:
        return {"status": "ok"}
    return {"status": "degraded", "checks": checks}


@app.get("/api/presence")
async def get_global_presence(
    pid: str | None = None,
    db: Annotated[Session, Depends(get_db)] = None,
    user: Annotated[models.User, Depends(get_current_user)] = None,
):
    from .core.access import check_pid_access as _check_pid
    from .core.access import get_user_member_pids as _get_pids

    # Security audit 2026-10-09 (LOW): used to leak every online username on
    # the platform to any authenticated caller (the member-pids result was
    # computed and discarded). Scope to the rooms of projects the caller
    # belongs to (org rooms stay visible — org membership governs those).
    member_pids = set(_get_pids(db, user))
    if pid:
        _check_pid(db, pid, user, "project.read")
        member_pids = {pid}
    online: list[str] = []
    for room in list(getattr(manager, "_rooms", {}).keys()):
        if not room.startswith("org:") and room not in member_pids:
            continue
        try:
            online.extend(await manager.get_presence(room))
        except Exception:
            pass
    return {"online": sorted({u.get("name") for u in online if isinstance(u, dict) and u.get("name")})}


# ── Modules endpoint ──────────────────────────────────────────────────
# Note: GET /api/modules is served by modules_api.router (routing.py).
# The old plugins.state.list_modules is accessible via /api/system/modules.


@app.get("/api/connectors")
def list_connectors():
    return {"connectors": registry.list_connectors()}


# ── Include all domain routers ────────────────────────────────────────
from .routing import register_all

register_all(app)


@app.get("/api/worker/status", tags=["worker"])
async def worker_status(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    from . import models as _models
    from .core.worker_pool import get_pool

    pool = get_pool()
    queued_db = db.query(_models.Job).filter(_models.Job.status == "queued").count()
    running_db = db.query(_models.Job).filter(_models.Job.status == "running").count()

    backend = os.environ.get("WORKER_BACKEND", "internal").lower()
    if backend == "arq":
        from .core.arq_pool import get_arq_pool
        from .core.arq_worker import ARQ_QUEUE_NAME

        arq_pool = get_arq_pool()
        arq_queue_size = 0
        if arq_pool is not None:
            try:
                arq_queue_size = await arq_pool.zcard(ARQ_QUEUE_NAME)
            except Exception:
                arq_queue_size = -1
        return {
            "backend": "arq",
            "arq_queue_size": arq_queue_size,
            "relay_queue_size": pool.queue_size,
            "queued_in_db": queued_db,
            "running_in_db": running_db,
        }

    return {
        "backend": "internal",
        "max_workers": pool._max_workers,
        "max_per_project": pool._max_per_project,
        "active": pool.active_count,
        "active_jobs": pool.active_jobs,
        "per_project": pool.per_project_counts,
        "queue_size": pool.queue_size,
        "queued_in_db": queued_db,
        "running_in_db": running_db,
    }
