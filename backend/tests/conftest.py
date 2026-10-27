import os
import socket
import tempfile
from pathlib import Path

# Extension modules (modules/*) mount their FastAPI routers at app startup.
# Must be set before `app` is imported. Two on-disk layouts are possible for
# this same conftest.py, and a fixed parents[N] picks the wrong one for the
# other layout (found running the CI Docker test image, which surfaced as
# every ioc-tracker API test 404ing — the module router silently never
# mounted because MODULES_DIR pointed at a nonexistent directory):
#   - host checkout:  .../<repo>/backend/tests/conftest.py -> modules is
#     two levels up, at .../<repo>/modules
#   - Dockerfile.test image: /app/tests/conftest.py, with /app being the
#     effective repo root and modules baked in at /app/modules — only one
#     level up
# Try both and use whichever actually exists on disk.
for _candidate in (
    Path(__file__).resolve().parents[1] / "modules",
    Path(__file__).resolve().parents[2] / "modules",
):
    if _candidate.is_dir():
        os.environ.setdefault("MODULES_DIR", str(_candidate))
        break

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, event, Table, Column, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import JSONB, ARRAY, INET, CIDR, UUID, HSTORE
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@compiles(ARRAY, "sqlite")
def _compile_array_sqlite(type_, compiler, **kw):
    return "JSON"@compiles(INET, "sqlite")
def _compile_inet_sqlite(type_, compiler, **kw):
    return "TEXT"


@compiles(CIDR, "sqlite")
def _compile_cidr_sqlite(type_, compiler, **kw):
    return "TEXT"


@compiles(UUID, "sqlite")
def _compile_uuid_sqlite(type_, compiler, **kw):
    return "TEXT"


@compiles(HSTORE, "sqlite")
def _compile_hstore_sqlite(type_, compiler, **kw):
    return "JSON"

os.environ["APP_ENV"] = "test"
os.environ.setdefault("UPLOAD_ROOT", tempfile.mkdtemp(prefix="umbryx_test_"))
os.environ.setdefault("SYNC_SIGNING_KEY", "test-sync-key")

# Prevent tests from hanging on real network calls (e.g. paramiko SSH connect)
socket.setdefaulttimeout(3)

from app.core.enums import UserRole
from app.core.security import hash_password
from app.core.utils import new_id, ts_now
from app.database import Base, get_db
from app.main import app
from app.models.auth import User

# Ensure rate limiter is disabled (it may have been created before APP_ENV was set)
try:
    from app.core.limiter import limiter as _limiter
    _limiter.enabled = False
except ImportError:
    pass

if "infra_instances" not in Base.metadata.tables:
    Table("infra_instances", Base.metadata, Column("id", String, primary_key=True))

# Postgres-CI (track C, 2026-10-09): point the suite at a real Postgres via
# SQLALCHEMY_TEST_URL (e.g. postgresql+psycopg2://umbryx:umbryx@localhost:5433/umbryx_test)
# to exercise the production dialect — pg_insert paths, JSONB columns, real
# partial/expression indexes. Default stays in-memory SQLite.
SQLALCHEMY_TEST_URL = os.environ.get("SQLALCHEMY_TEST_URL", "sqlite://")
_IS_SQLITE = SQLALCHEMY_TEST_URL.startswith("sqlite")

# Under pytest-xdist every worker is a separate process. SQLite workers
# each get their own in-memory engine — but a shared SQLALCHEMY_TEST_URL
# (the CI postgres job) would point every worker at ONE database and
# the parallel suites would collide on unique keys. Give each worker
# its own database: append the xdist worker id (gw0, gw1, …) to the
# database name and create it up front.
if not _IS_SQLITE:
    _xdist_worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    if _xdist_worker and _xdist_worker != "master":
        from sqlalchemy.engine.url import make_url

        _u = make_url(SQLALCHEMY_TEST_URL)
        _u = _u.set(database=f"{_u.database}_{_xdist_worker}")
        _admin = create_engine(make_url(SQLALCHEMY_TEST_URL).set(database="postgres"), isolation_level="AUTOCOMMIT")
        with _admin.connect() as _c:
            _exists = _c.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": _u.database}
            ).scalar()
            if not _exists:
                try:
                    _c.execute(text(f'CREATE DATABASE "{_u.database}"'))
                except Exception:  # noqa: BLE001 — lost a create-race: fine
                    pass
        _admin.dispose()
        # str(url) MASKS the password as *** — the engine would then
        # authenticate with a literal "***" password. Render explicitly.
        SQLALCHEMY_TEST_URL = _u.render_as_string(hide_password=False)

if _IS_SQLITE:
    engine = create_engine(
        SQLALCHEMY_TEST_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    # One shared connection for the whole suite (same as the SQLite path):
    # per-test nested-transaction rollback must also undo commits made by
    # other sessions (HTTP calls through TestClient), which only works when
    # every session shares a single DBAPI connection.
    engine = create_engine(
        SQLALCHEMY_TEST_URL,
        poolclass=StaticPool,
        connect_args={"application_name": "umbryx-tests"},
    )
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_override_stack = []


if _IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "before_cursor_execute")
    def _serialize_lists_for_sqlite(conn, cursor, statement, parameters, context, executemany):
        """SQLite can't bind Python lists/dicts directly — convert to JSON strings."""
        if not parameters:
            return
        import json

        def _convert(val):
            if isinstance(val, list):
                return json.dumps(val)
            if isinstance(val, dict):
                return json.dumps(val)
            return val

        if isinstance(parameters, dict):
            for k, v in parameters.items():
                parameters[k] = _convert(v)
        elif isinstance(parameters, (list, tuple)):
            if parameters and isinstance(parameters[0], dict):
                for row in parameters:
                    for k, v in row.items():
                        row[k] = _convert(v)
            else:
                parameters = type(parameters)(_convert(v) for v in parameters)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    # Background tasks (e.g. run_queued_job) open their own session via
    # SessionLocal instead of the get_db dependency, so the dependency override
    # alone doesn't redirect them to the test DB. Rebind SessionLocal in every
    # namespace that imported it directly so those tasks hit the in-memory DB.
    import app.database as _database

    _database.SessionLocal = TestingSessionLocal
    try:
        import app.core.job_runner as _job_runner

        _job_runner.SessionLocal = TestingSessionLocal
    except (ImportError, AttributeError):
        pass
    try:
        # Attacker-target / module-state lookups open their own sessions
        # (db=None paths in attacker_transport).
        import app.plugins.state as _plugin_state

        _plugin_state.SessionLocal = TestingSessionLocal
    except (ImportError, AttributeError):
        pass
    try:
        # Playbook engine helpers (_wait_for_job/_resume_run_after_approval)
        # open their own sessions the same way background tasks do.
        import app.routers.playbooks._engine as _pb_engine

        _pb_engine.SessionLocal = TestingSessionLocal
    except (ImportError, AttributeError):
        pass
    try:
        import app.routers.workstations as _ws_router

        _ws_router.SessionLocal = TestingSessionLocal
    except (ImportError, AttributeError):
        pass

    _init_schema()
    yield
    Base.metadata.drop_all(bind=engine)


def _init_schema() -> None:
    """Create tables + dialect indexes and seed the admin user. Called
    once per session and again before EVERY test file (see
    _fresh_state_per_file)."""
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS global_settings "
            "(key TEXT PRIMARY KEY, value JSONB NOT NULL DEFAULT '{}')"
        ))
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_hosts_pid_ip
                ON hosts (pid, ip) WHERE ip IS NOT NULL AND ip <> '';
        """))
        # PG needs expression-index columns parenthesised; SQLite accepts both forms
        _coalesce = "(COALESCE(domain, '')), (COALESCE(host, ''))" if not _IS_SQLITE else \
            "COALESCE(domain, ''), COALESCE(host, '')"
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_creds_pid_user_domain_host "
            f"ON creds (pid, username, {_coalesce}) "
            "WHERE username IS NOT NULL AND username <> '';"
        ))
    _session = TestingSessionLocal()
    if not _session.query(User).filter_by(username="admin").first():
        _session.add(User(
            id=new_id("u"),
            username="admin",
            display_name="admin",
            password_hash=hash_password("TestPass1234!"),
            role=UserRole.PLATFORM_ADMIN,
            created_at=ts_now(),
            active=True,
        ))
        _session.commit()
    _session.close()


@pytest.fixture(scope="module", autouse=True)
def _fresh_state_per_file(setup_db):
    """A clean database for EVERY test file.

    Under xdist --dist loadfile a worker runs many files against one
    database, and loadfile's file-to-worker assignment is timing-based —
    each run pairs different files as neighbours. The suite was written
    for one fixed sequential order; leaked rows (global_settings, users,
    droppers, license state) made outcomes grouping-dependent: the same
    commit failed CI with tenancy/host-registration errors and locally
    with ai-manager/notifications errors, never the same twice. A
    per-file reset restores the fresh-per-module semantics every fixture
    was actually written against — and retires the documented
    order-dependence of the license modules with it.

    Postgres: one TRUNCATE over all tables (instant). SQLite: drop_all +
    recreate (the in-memory schema rebuild is a few hundred ms).
    """
    if _IS_SQLITE:
        Base.metadata.drop_all(bind=engine)
        _init_schema()
    else:
        _tables = ", ".join(f'"{t}"' for t in sorted(Base.metadata.tables))
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE {_tables} RESTART IDENTITY CASCADE"))
        _session = TestingSessionLocal()
        _session.add(User(
            id=new_id("u"),
            username="admin",
            display_name="admin",
            password_hash=hash_password("TestPass1234!"),
            role=UserRole.PLATFORM_ADMIN,
            created_at=ts_now(),
            active=True,
        ))
        _session.commit()
        _session.close()
    yield


@pytest.fixture()
def db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# Session-scoped TestClient: the app lifespan (extension-module load +
# router mount) runs ONCE per pytest process. It used to wrap every
# function-scoped client in `with TestClient(app)`, re-running lifespan
# per test — module loaders re-read manifests and, worse,
# activate_loaded_modules() re-mounted module routers each time,
# growing the app route table linearly across the run (first-match
# wins, so tests kept passing while every request got slower).
# Test-mode lifespan touches no DB/pool/scheduler (see app/main.py), so
# sharing it across tests is safe; per-test state isolation comes from
# the get_db override swap below.
@pytest.fixture(scope="session")
def _session_client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def client(db, _session_client):
    import httpx

    def override_get_db():
        try:
            yield db
        finally:
            pass

    _prev = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    # Private cookie jar per test: the lifespan/client is shared across
    # the session, but a fresh TestClient used to guarantee every test
    # starts unauthenticated ("no token → 401" tests would otherwise
    # ride a previous test's login cookie). Swapping the jar (not
    # clearing it) keeps OTHER scopes' jars intact — a module_client
    # bootstrap login in the same worker must survive this test.
    _saved_jar = _session_client.cookies
    _session_client.cookies = httpx.Cookies()
    yield _session_client
    _session_client.cookies = _saved_jar
    if _prev is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = _prev


@pytest.fixture(scope="module")
def module_monkeypatch():
    """Module-scoped monkeypatch (pytest's built-in is function-scoped) — for
    module-scoped bootstraps that need to patch, e.g. the license verifier's
    public key when applying a test license."""
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def module_db():
    session = TestingSessionLocal()
    admin = session.query(User).filter_by(username="admin").first()
    if admin:
        admin.password_hash = hash_password("TestPass1234!")
        admin.mfa_enabled = False
        admin.totp_secret = None
    else:
        session.add(User(
            id=new_id("u"),
            username="admin",
            display_name="admin",
            password_hash=hash_password("TestPass1234!"),
            role=UserRole.PLATFORM_ADMIN,
            created_at=ts_now(),
            active=True,
        ))
    session.commit()
    yield session
    session.close()


@pytest.fixture(scope="module")
def module_client(module_db, _session_client):
    import httpx

    def override_get_db():
        if not module_db.is_active:
            module_db.rollback()
        yield module_db

    _override_stack.append(override_get_db)
    app.dependency_overrides[get_db] = override_get_db
    # reuses the session-scoped lifespan client — no per-module app
    # bootstrap / router re-mount (see _session_client). One private
    # cookie jar PER MODULE = the old fresh-TestClient semantics: a
    # module bootstrap login persists for the module's tests, without
    # leaking into other modules or being clobbered by interleaved
    # function-scoped client tests.
    _saved_jar = _session_client.cookies
    _session_client.cookies = httpx.Cookies()
    yield _session_client
    _session_client.cookies = _saved_jar
    _override_stack.pop()
    if _override_stack:
        app.dependency_overrides[get_db] = _override_stack[-1]
    else:
        app.dependency_overrides.pop(get_db, None)


def pytest_collection_modifyitems(config, items):
    """Skip `ee`-marked tests when the Enterprise package is not in the build.

    A Community artifact is the same test suite minus the Enterprise code
    (docs/modules/EDITIONS.md), so its run has to distinguish "this fails"
    from "this does not apply". Marked tests become skips rather than
    failures, and the Enterprise run is untouched — the marker only does
    anything when app.ee is absent.

    Tests whose module imports app.ee at import time cannot be handled
    here, because collection fails before the marker is read. Those
    declare pytest.importorskip("app.ee") themselves.
    """
    from app.core.editions import ee_available

    if ee_available():
        return
    skip_ee = pytest.mark.skip(reason="Enterprise Edition package not in this build")
    for item in items:
        if "ee" in item.keywords:
            item.add_marker(skip_ee)
