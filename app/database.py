import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

def pool_kwargs_for(database_url: str) -> dict:
    """
    create_engine() pool arguments for a database URL.

    SQLite gets none. A file-backed SQLite URL happens to use QueuePool and would
    tolerate them, but ":memory:" uses SingletonThreadPool and raises TypeError on
    max_overflow/pool_timeout — at import time, so the server would not start at all.
    Neither pool means anything for SQLite anyway: there is no connection to keep alive.

    Everything else gets a bounded, self-healing pool. pool_pre_ping is the one that
    shows up in production: MySQL closes idle connections after wait_timeout (8h by
    default) and a PostgreSQL pooler drops them sooner, so without it the first request
    onto every cached connection after an idle period fails with a stale-connection
    error. pool_recycle retires connections before the server does.

    Split out of the module body so it can be asserted on without importing this module
    under a second DATABASE_URL. See Settings.DB_POOL_SIZE for the sizing.
    """
    if database_url.startswith("sqlite"):
        return {}
    return {
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_timeout": settings.DB_POOL_TIMEOUT_SECONDS,
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }


connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    **pool_kwargs_for(settings.DATABASE_URL),
)


def _sqlite_path(url: str) -> Path | None:
    """Filesystem path behind a sqlite URL, or None for other backends and :memory:."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return None
    raw = url[len(prefix):]
    if not raw or raw == ":memory:":
        return None
    return Path(raw)


def _restrict_sqlite_permissions(db_path: Path) -> None:
    """
    Keep the database file owner-only.

    SQLite creates it with the process umask, normally 0644. The file holds bcrypt
    password hashes, Fernet-encrypted TOTP secrets, API key hashes and the encrypted
    vehicle passwords — everything needed to work offline against the deployment.
    The .env and the log files were already tightened; the database never was.

    Applied on every connect rather than once at creation, so a file that predates
    this (or that a restore dropped in at 0644) is corrected too.
    """
    try:
        if not db_path.exists():
            return
        current = db_path.stat().st_mode & 0o777
        if current & 0o077:
            os.chmod(db_path, 0o600)
            logger.warning(
                f"Tightened permissions on {db_path} from {current:04o} to 0600."
            )
    except OSError as e:
        # Never block startup on this — a read-only mount or an unusual owner is a
        # deployment decision, and refusing to run would be the worse failure.
        logger.warning(f"Could not adjust permissions on {db_path}: {e}")


_SQLITE_PATH = _sqlite_path(settings.DATABASE_URL)
if _SQLITE_PATH is not None:
    @event.listens_for(engine, "connect")
    def _harden_sqlite_file(dbapi_connection, connection_record):  # noqa: ARG001
        _restrict_sqlite_permissions(_SQLITE_PATH)


if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _tune_sqlite(dbapi_connection, connection_record):  # noqa: ARG001
        """
        Make SQLite survive concurrent writers.

        On the defaults it does not, and this server has many: the two MQTT subscribers,
        the charge manager, the 2 s broadcaster, the TCP servers and every request.

        * journal_mode=WAL — the rollback journal takes a database-wide exclusive lock
          for the duration of every write, so readers block on writers and writers block
          on each other. WAL lets readers carry on while a write is in progress, which is
          the single biggest difference for a workload that is mostly small writes from
          background threads.
        * busy_timeout — without it a writer that finds the database locked fails
          *immediately* with "database is locked" rather than waiting. The Python default
          is 5 s; naming it makes the value deliberate rather than inherited.
        * synchronous=NORMAL — under WAL this is the documented safe pairing: durable
          against a process crash, and only at risk of losing the last transactions if
          the machine itself loses power. FULL fsyncs on every commit, which is what made
          the per-record history writes so expensive.

        Deliberately *not* here: `PRAGMA foreign_keys=ON`. SQLite ignores foreign keys
        unless asked, per connection, and turning that on is a correctness change rather
        than a latency one — it makes deletes that this codebase currently performs start
        failing, because the ordering they rely on has never been enforced. That is worth
        doing, and worth doing on its own, with the delete paths audited alongside it.

        None of this applies to PostgreSQL or MySQL deployments, which is where the real
        fleets run; it is here so that a SQLite install (the default in config.py) does
        not have a write-latency problem the other backends do not.
        """
        cursor = dbapi_connection.cursor()
        try:
            # WAL is a persistent property of the file and meaningless for :memory:.
            if _SQLITE_PATH is not None:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
        except Exception as e:  # pragma: no cover - a PRAGMA must never block startup
            logger.warning(f"Could not apply SQLite tuning PRAGMAs: {e}")
        finally:
            cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db_models_import():
    """
    Import every model module for its side effect: defining a class that inherits from
    Base registers it on Base.metadata, and nothing else in the startup path imports the
    charge logger's models. Called from bootstrap.initialize_services().

    The noqa markers are load-bearing. These names are deliberately unused — that is the
    whole point of the function — and `ruff --fix` duly deleted both lines and left this
    body as `pass`, which silently empties the metadata the migrations are checked
    against. Do not remove them, and do not "clean up" this function.
    """
    from app.models import db as models_db  # noqa: F401
    from app.services.charge_logger import models as charge_logger_models  # noqa: F401