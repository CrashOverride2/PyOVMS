"""
Route handlers must not do blocking work on the event loop.

The server runs the V2 TCP listeners, the two-second WebSocket broadcaster and every HTTP
request on one asyncio loop. A handler declared `async def` runs *on* that loop, so every
synchronous SQLAlchemy call inside it stalls all three at once — a slow query does not
just slow one request down, it stops vehicles from being able to report in.

FastAPI already solves this: a handler declared as a plain `def` is dispatched to a
threadpool, and blocking there costs a thread instead of the loop. So the rule is simple —
if a handler never awaits, it has no business being a coroutine.

93 handlers were `async def` without a single `await` in the body when this test was
written. This is the guard that keeps the next one from being added.
"""

import ast
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ROUTERS = REPO_ROOT / "app" / "routers"

_HTTP_METHODS = (".get(", ".post(", ".put(", ".delete(", ".patch(", ".head(", ".options(")


def _http_route_handlers():
    """Every HTTP route handler in app/routers, as (path, node). WebSocket handlers are
    excluded: those legitimately stay coroutines even without an obvious await, because
    the protocol itself is async."""
    for path in sorted(ROUTERS.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = " ".join(ast.unparse(d) for d in node.decorator_list)
            if "websocket" in decorators:
                continue
            if any(method in decorators for method in _HTTP_METHODS):
                yield path.relative_to(REPO_ROOT), node


def _awaits_anything(node: ast.AST) -> bool:
    return any(
        isinstance(sub, (ast.Await, ast.AsyncFor, ast.AsyncWith)) for sub in ast.walk(node)
    )


ALL_HANDLERS = list(_http_route_handlers())


def test_the_scan_still_finds_the_routes():
    """A guard whose subject silently becomes an empty set passes forever. If the routers
    move, this fails first and says so."""
    assert len(ALL_HANDLERS) > 90, (
        f"Only {len(ALL_HANDLERS)} route handlers found under app/routers — the scan in "
        "this test has stopped matching how routes are declared."
    )


@pytest.mark.parametrize(
    "path, handler",
    [(p, n) for p, n in ALL_HANDLERS if isinstance(n, ast.AsyncFunctionDef)],
    ids=lambda v: v.name if isinstance(v, ast.AST) else str(v),
)
def test_async_handlers_actually_await_something(path, handler):
    assert _awaits_anything(handler), (
        f"{path}:{handler.lineno} {handler.name}() is declared `async def` but never awaits. "
        "It therefore runs its blocking work — database queries, template rendering — "
        "directly on the event loop, stalling the V2 TCP listeners and the WebSocket "
        "broadcaster along with it. Drop the `async` and FastAPI will run it in a "
        "threadpool instead."
    )


def test_sync_handlers_are_the_common_case():
    """Stated as a property rather than a fixed count so ordinary route work does not
    fail the build, while a wholesale return to `async def` everywhere does."""
    sync = sum(1 for _, n in ALL_HANDLERS if isinstance(n, ast.FunctionDef))
    assert sync >= 0.7 * len(ALL_HANDLERS), (
        f"Only {sync} of {len(ALL_HANDLERS)} route handlers are plain `def`. Handlers that "
        "do synchronous database work belong in the threadpool; if a batch of them has "
        "genuinely become async-native, update this threshold deliberately."
    )
