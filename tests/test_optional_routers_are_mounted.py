"""
Optional routers must actually be mounted, not silently skipped.

app/main.py imports the Charge Logger router inside `try/except ImportError` and, on
failure, logs an error and sets the router to None. The server then starts normally,
serves every other route, and passes the entire test suite — with the Charge Log API
missing. The only evidence is one ERROR line in a startup log nobody reads.

That is not hypothetical. Cleaning up unused imports deleted the re-export line in
app/services/charge_logger/database.py, which is what api.py imports get_db from. Boot
still succeeded; the whole feature was gone.

If a router is genuinely meant to be optional, gate it on a setting and assert the
setting here. `except ImportError: pass` is not a feature flag.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402
from conftest import iter_http_routes  # noqa: E402


def _mounted_paths() -> set[str]:
    # Not `app.routes`: under the pinned Starlette that list hides every included router
    # behind a wrapper. See iter_http_routes() in conftest.py.
    return {route.path for route in iter_http_routes(app)}


def test_charge_logger_router_is_mounted():
    charge_routes = sorted(p for p in _mounted_paths() if "charge" in p.lower())

    assert charge_routes, (
        "No Charge Log routes are mounted. app/main.py caught an ImportError from "
        "app.services.charge_logger.api and disabled the router — check the startup log "
        "for 'Could not import Charge Logger service router'. The server starts fine "
        "without it, which is exactly why this needs a test."
    )


def test_charge_logger_reexports_are_intact():
    """The specific import that broke. Asserted directly so the failure names the cause
    instead of the symptom."""
    from app.services.charge_logger import database

    assert hasattr(database, "get_db"), (
        "app/services/charge_logger/database.py no longer re-exports get_db. That module "
        "exists only for these re-exports; api.py imports get_db from it."
    )
    assert hasattr(database, "SessionLocal")


def test_core_routers_are_mounted():
    """A blunt check that the three routing tables are all present — if one of these is
    empty, something in main.py's include_router chain failed."""
    paths = _mounted_paths()

    assert any(p.startswith("/api/v1/vehicles") for p in paths), "API router missing"
    assert any(p == "/health" for p in paths), "health endpoint missing"
    assert any(p.startswith("/ws") for p in paths), "WebSocket router missing"
