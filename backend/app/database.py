import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import QueuePool

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite://")

_pool_size = int(os.environ.get("DATABASE_POOL_SIZE", "10"))
_max_overflow = int(os.environ.get("DATABASE_MAX_OVERFLOW", "20"))
_pool_recycle = int(os.environ.get("DATABASE_POOL_RECYCLE", "1800"))
_statement_timeout = int(os.environ.get("DATABASE_STATEMENT_TIMEOUT", "30000"))

_connect_args = {}
_engine_kwargs = {
    "pool_pre_ping": True,
}

if DATABASE_URL.startswith("sqlite"):
    from sqlalchemy.pool import StaticPool

    _engine_kwargs["poolclass"] = StaticPool
    _connect_args["check_same_thread"] = False
else:
    _engine_kwargs["poolclass"] = QueuePool
    _engine_kwargs["pool_size"] = _pool_size
    _engine_kwargs["max_overflow"] = _max_overflow
    _engine_kwargs["pool_recycle"] = _pool_recycle
    # TCP keepalives: without these, a connection open when the backend
    # dies (e.g. a Postgres failover behind a TCP-passthrough LB/VIP) never
    # gets an RST — the peer just stops responding — so a pooled
    # connection's socket sits "established" forever from the OS's point
    # of view. pool_pre_ping's `SELECT 1` then blocks on that same dead
    # socket instead of catching it, so every request that draws that
    # connection hangs indefinitely instead of failing over to a healthy
    # replica. Found live: killed the primary behind a pg_auto_failover +
    # HAProxy + keepalived VIP setup — a fresh `psql` through the VIP
    # recovered instantly, but the app's existing pool hung >40s.
    # Keepalive probes after 5s idle, every 2s, 3 tries — bounds the
    # worst case to ~11s before the socket is reported dead.
    _connect_args["keepalives"] = 1
    _connect_args["keepalives_idle"] = 5
    _connect_args["keepalives_interval"] = 2
    _connect_args["keepalives_count"] = 3
    _connect_args["connect_timeout"] = 10

engine = create_engine(DATABASE_URL, connect_args=_connect_args, **_engine_kwargs)

if _statement_timeout and not DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _set_statement_timeout(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"SET statement_timeout = {_statement_timeout}")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_replica_engine = None


def get_replica_engine():
    """Return the read replica engine if configured, else the primary engine."""
    global _replica_engine
    if _replica_engine is not None:
        return _replica_engine
    replica_url = os.environ.get("DATABASE_REPLICA_URL")
    if replica_url:
        _replica_engine = create_engine(
            replica_url,
            poolclass=QueuePool,
            pool_size=int(os.environ.get("DATABASE_POOL_SIZE", "10")),
            max_overflow=int(os.environ.get("DATABASE_MAX_OVERFLOW", "20")),
            pool_recycle=int(os.environ.get("DATABASE_POOL_RECYCLE", "1800")),
            pool_pre_ping=True,
            connect_args={
                "keepalives": 1,
                "keepalives_idle": 5,
                "keepalives_interval": 2,
                "keepalives_count": 3,
                "connect_timeout": 10,
            },
        )
        return _replica_engine
    return engine


ReadSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_replica_engine())


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_read_db():
    """Yield a session from the read replica (or primary if no replica configured)."""
    db = ReadSessionLocal()
    try:
        yield db
    finally:
        db.close()
