"""Shared pytest configuration.

The test suite must never touch the developer's demo database, so an isolated
temporary data directory and SQLite file are configured *before* any ``app``
module is imported (settings are read at import time).
"""
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

_TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="agentfence_tests_"))
os.environ["AGENTFENCE_DATA_DIR"] = str(_TEST_DATA_DIR)
os.environ["DATABASE_URL"] = f"sqlite:///{(_TEST_DATA_DIR / 'test.db').as_posix()}"
os.environ.setdefault("AGENTFENCE_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("AGENTFENCE_ENV", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def pytest_sessionfinish(session, exitstatus):
    try:
        from app.database.session import engine
        engine.dispose()
    except Exception:
        pass
    shutil.rmtree(_TEST_DATA_DIR, ignore_errors=True)
