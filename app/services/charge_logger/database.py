# This file allows the charge_logger service to have its own logical database
# module while reusing the main application's database connection and session.
#
# These re-exports are the entire purpose of the module — app/services/charge_logger/api.py
# imports get_db from here, not from app.database. The noqa is load-bearing: `ruff --fix`
# removed this line as an unused import, and because app/main.py wraps the charge logger
# router import in `except ImportError` and only logs, the whole Charge Log API silently
# disappeared from a server that still started, still served every other route and still
# passed the test suite.
from app.database import get_db, SessionLocal  # noqa: F401

__all__ = ["get_db", "SessionLocal"]
