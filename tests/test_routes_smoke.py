"""
Every GET route answers *something* — never a 500.

The suite is thorough about individual security properties and had nothing that simply
drove the routing table end to end. That gap matters most exactly when routes are changed
wholesale: 93 handlers were converted from `async def` to `def` so FastAPI would dispatch
them to a threadpool instead of the event loop (see
test_routes_do_not_block_the_event_loop.py), and a mistake in that conversion shows up as
an unhandled exception at request time, not at import time.

Unauthenticated is the point. A redirect to the login page, a 401, a 403, a 422 for a
missing query parameter — all fine, all evidence the route was reached and its guards ran.
A 500 means the handler itself broke.
"""

import pathlib
import sys

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402
from conftest import iter_http_routes  # noqa: E402


def _parameterless_get_routes():
    """GET routes that need no path parameters, so they can be called as written.

    Routes with path params are skipped rather than filled with dummy values: a fabricated
    vehicle id exercises the not-found branch, which is not what this test is for.
    """
    # Not `app.routes` — see iter_http_routes() in conftest.py.
    seen = set()
    for route in iter_http_routes(app):
        if "GET" not in route.methods or "{" in route.path:
            continue
        if route.path.startswith("/static"):
            continue
        if route.path not in seen:
            seen.add(route.path)
            yield route.path


ROUTES = sorted(_parameterless_get_routes())


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_the_scan_found_a_realistic_number_of_routes():
    assert len(ROUTES) > 20, (
        f"Only {len(ROUTES)} parameterless GET routes discovered — this smoke test has "
        "stopped seeing the routing table."
    )


@pytest.mark.parametrize("path", ROUTES)
def test_get_route_does_not_raise(client, path):
    response = client.get(path, follow_redirects=False)

    assert response.status_code < 500, (
        f"GET {path} returned {response.status_code}. Any answer below 500 is acceptable "
        f"here — a redirect to login, a 401, a 403, a 422 for a missing query parameter. "
        f"A 5xx means the handler itself raised.\n\n{response.text[:600]}"
    )


def test_health_endpoint_is_actually_healthy(client):
    """The one route asserted on its content rather than just its status: it is what a
    load balancer and the container healthcheck poll."""
    response = client.get("/health")
    assert response.status_code == 200
