"""
Guards for the two ways a database session outlives the error that broke it.

Both failures here are silent by construction: nothing crashes, no request 500s, the
process keeps running and the logs fill with a follow-on error that does not name the
cause. That is precisely the shape a test has to catch, because operating the server
will not.
"""

import ast
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _function_named(module_path: pathlib.Path, name: str):
    tree = ast.parse(module_path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    pytest.fail(f"{module_path.name} no longer defines {name}() — update this test.")


def _calls_rollback(node: ast.AST) -> bool:
    """Matches `db.rollback()` and `run_in_threadpool(db.rollback)` alike — the second is
    the form the broadcaster uses, since rollback() is a blocking round-trip and this runs
    on the event loop."""
    return any(
        isinstance(sub, ast.Attribute) and sub.attr == "rollback" for sub in ast.walk(node)
    )


class TestBroadcasterSessionRecovers:
    """
    periodic_vehicle_data_broadcaster opens one Session and keeps it for the lifetime of
    the process. That is a reasonable choice for a task that runs every two seconds, but
    it makes rollback mandatory rather than optional: a single failed statement — a
    dropped connection, a lock timeout, a deadlock victim — leaves the session in a
    failed transaction, and SQLAlchemy then answers *every* later statement with
    PendingRollbackError instead of touching the database.

    The loop catches and logs that, so the process survives and the log shows only the
    follow-on error. The visible symptom is that live dashboard data stops arriving and
    never comes back until someone restarts the server.
    """

    LIFESPAN = REPO_ROOT / "app" / "lifespan.py"

    def test_session_is_still_long_lived(self):
        """The precondition for the rest of this class. If the broadcaster ever moves to
        a per-cycle session, the rollback requirement goes away and these tests should be
        deleted rather than worked around."""
        fn = _function_named(self.LIFESPAN, "periodic_vehicle_data_broadcaster")
        loop_bodies = [n for n in ast.walk(fn) if isinstance(n, (ast.While, ast.For))]
        opens_in_loop = any(
            isinstance(call.func, ast.Name) and call.func.id == "SessionLocal"
            for loop in loop_bodies
            for call in ast.walk(loop)
            if isinstance(call, ast.Call)
        )
        assert not opens_in_loop, (
            "The broadcaster now opens a session inside its loop. That is fine — but it "
            "makes this whole test class obsolete. Delete it."
        )

    def test_every_handler_in_the_loop_rolls_back(self):
        """Every `except` inside the broadcast loop must roll the session back before the
        next iteration reuses it."""
        fn = _function_named(self.LIFESPAN, "periodic_vehicle_data_broadcaster")

        loops = [n for n in ast.walk(fn) if isinstance(n, ast.While)]
        assert loops, "periodic_vehicle_data_broadcaster() has no loop — update this test."

        handlers = [h for loop in loops for h in ast.walk(loop) if isinstance(h, ast.ExceptHandler)]
        assert handlers, "The broadcast loop no longer catches anything — update this test."

        # The rollback call is itself wrapped in a try/except (a broken connection can
        # fail the rollback too), so ignore handlers that sit inside a rollback attempt.
        outer = [h for h in handlers if not _calls_rollback_ancestor(fn, h)]

        missing = [h.lineno for h in outer if not _calls_rollback(h)]
        assert not missing, (
            f"except handler(s) at line(s) {missing} in periodic_vehicle_data_broadcaster() "
            "log the error but do not roll the shared session back. The next iteration will "
            "raise PendingRollbackError, and the dashboard stops updating until restart."
        )


def _calls_rollback_ancestor(root: ast.AST, target: ast.ExceptHandler) -> bool:
    """True if `target` is the handler guarding a rollback call, rather than a handler
    that ought to perform one."""
    for node in ast.walk(root):
        if isinstance(node, ast.Try) and target in node.handlers:
            return any(_calls_rollback(stmt) for stmt in node.body)
    return False


class TestPoolConfiguration:
    """
    Without pool_pre_ping a pooled connection is handed out after the server on the other
    end has already closed it, and the request fails on a connection that looked healthy.
    MySQL does this after wait_timeout (8 hours by default); a PostgreSQL pooler does it
    sooner. The failure lands on whichever request happens to draw the stale connection
    first, which makes it look intermittent and unrelated to idleness.
    """

    def test_sqlite_gets_no_pool_arguments(self):
        """':memory:' uses SingletonThreadPool, which raises TypeError on max_overflow and
        pool_timeout. Passing them would break startup, not degrade it."""
        from app.database import pool_kwargs_for

        assert pool_kwargs_for("sqlite:///./ovms_py.db") == {}
        assert pool_kwargs_for("sqlite:///:memory:") == {}

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql://user:pw@localhost:5432/ovms",
            "postgresql+psycopg2://user:pw@localhost:5432/ovms",
            "mysql+pymysql://user:pw@localhost:3306/ovms",
        ],
    )
    def test_server_backends_get_a_bounded_self_healing_pool(self, url):
        from app.config import settings
        from app.database import pool_kwargs_for

        kwargs = pool_kwargs_for(url)

        assert kwargs["pool_pre_ping"] is True, (
            "pool_pre_ping is off: the first request onto every cached connection after "
            "an idle period will fail with a stale-connection error."
        )
        assert kwargs["pool_recycle"] > 0, (
            "pool_recycle is unset: connections are never retired, so the server on the "
            "other end gets to close them first."
        )
        assert kwargs["pool_timeout"] == settings.DB_POOL_TIMEOUT_SECONDS
        assert kwargs["pool_timeout"] > 0, (
            "Without a pool timeout a caller that cannot get a connection waits forever. "
            "The V2 TCP listeners and the 2s broadcaster share this event loop."
        )
        assert kwargs["pool_size"] == settings.DB_POOL_SIZE
        assert kwargs["max_overflow"] == settings.DB_MAX_OVERFLOW

    def test_sizing_leaves_room_for_karto(self):
        """Karto normally points at the same PostgreSQL server with the same defaults, so
        the ceiling that matters is both pools together against max_connections (100 by
        default). Raising one side alone is how you find out what happens when the other
        cannot get a connection."""
        from app.config import settings

        both_services_at_full_stretch = 2 * (settings.DB_POOL_SIZE + settings.DB_MAX_OVERFLOW)
        assert both_services_at_full_stretch <= 80, (
            f"OVMS and Karto together can demand {both_services_at_full_stretch} connections. "
            "PostgreSQL's default max_connections is 100, minus superuser_reserved_connections "
            "and anything else on that server. Raise max_connections deliberately or lower "
            "the pool, but do not let this drift silently."
        )
