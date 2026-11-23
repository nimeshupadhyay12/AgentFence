"""AgentFence database session, initialisation and schema-version guard."""
import logging
import shutil
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.base import Base

log = logging.getLogger("agentfence.db")

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if _is_sqlite else {},
    echo=False,
)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=30000")
        if ":memory:" not in settings.DATABASE_URL:
            cur.execute("PRAGMA journal_mode=WAL")
        cur.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class SchemaMismatchError(RuntimeError):
    pass


def _archive_legacy_sqlite() -> str:
    """Moves an incompatible (v1) SQLite database aside so that its audit chain
    is preserved and can still be checked with ``scripts/audit_cli.py verify-legacy``."""
    db_path = settings.DATABASE_URL.replace("sqlite:///", "", 1)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archived = f"{db_path}.v1-{stamp}.bak"
    engine.dispose()
    shutil.move(db_path, archived)
    for suffix in ("-wal", "-shm"):
        try:
            shutil.move(db_path + suffix, archived + suffix)
        except FileNotFoundError:
            pass
    return archived


def init_db() -> None:
    import app.models.entities  # noqa: F401  (registers models on Base.metadata)
    from app.models.entities import SCHEMA_VERSION, SchemaMeta

    existing = set(inspect(engine).get_table_names())
    if existing and "agentfence_meta" not in existing:
        # Pre-2.0 database: schema and audit-hash format are incompatible.
        if _is_sqlite and settings.is_dev:
            archived = _archive_legacy_sqlite()
            log.warning("Archived legacy v1 database to %s and created a fresh v2 schema", archived)
        else:
            raise SchemaMismatchError(
                "Database predates schema v2. Archive it (keep it for audit) and start with an empty database."
            )

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        meta = db.get(SchemaMeta, "schema_version")
        if meta is None:
            db.add(SchemaMeta(key="schema_version", value=SCHEMA_VERSION))
            db.commit()
        elif meta.value != SCHEMA_VERSION:
            raise SchemaMismatchError(f"Database schema v{meta.value} does not match code schema v{SCHEMA_VERSION}")


@contextmanager
def get_db():
    db: Session = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
