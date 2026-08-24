"""
Guards for iter_http_routes() itself — the helper the route tests are built on.

A broken inventory does not fail loudly. It reports fewer routes, or reports them under
the wrong URL, and every test built on it goes green while checking nothing. Both failure
modes have already happened here once:

  * Reading `app.routes` directly returned nine entries under the pinned Starlette (1.5),
    which wraps each included router instead of copying its routes into the parent. The
    same code returned everything under the development virtualenv, so the tests passed
    locally and failed against requirements.txt.
  * Walking into the wrapper but ignoring `include_context.prefix` produced '/suggest-id'
    instead of '/vehicle/suggest-id'. Nothing failed — the smoke test simply requested
    URLs that do not exist, collected 404s, and reported success.

The second one is why this file exists. A test that verifies a route answers is only worth
having if it asked for the right route.
"""

import pathlib
import sys

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402
from conftest import iter_http_routes  # noqa: E402

ROUTES = iter_http_routes(app)


def test_the_inventory_is_not_almost_empty():
    """The `app.routes`-returns-nine failure, stated as a floor. The real number is over a
    hundred; anything near nine means the traversal stopped at the wrappers."""
    assert len(ROUTES) > 100, (
        f"Only {len(ROUTES)} routes found. iter_http_routes() is not walking into the "
        "included routers — see its docstring."
    )


def test_known_prefixed_routes_appear_with_their_prefix():
    """The silent failure. These three are declared in routers included under a prefix, so
    each is proof that the prefix survived the walk."""
    paths = {route.path for route in ROUTES}

    for expected, bare in [
        ("/vehicle/suggest-id", "/suggest-id"),
        ("/api/v1/apikeys", "/apikeys"),
        ("/admin/security-events", "/security-events"),
    ]:
        assert expected in paths, (
            f"{expected} is missing from the inventory. If {bare} is present instead, the "
            "router prefix is being dropped and every URL-based test is requesting a path "
            "that does not exist."
        )
        assert bare not in paths, f"{bare} appears unprefixed — the prefix was lost"


def test_no_route_path_is_relative():
    bad = [route.path for route in ROUTES if not route.path.startswith("/")]
    assert bad == [], f"routes with a non-absolute path: {bad}"


@pytest.mark.parametrize(
    "path", ["/vehicle/suggest-id", "/api/v1/apikeys", "/admin/security-events"]
)
def test_the_inventoried_paths_are_really_routable(path):
    """The end of the argument: ask the application. Anything but 404 proves the URL
    exists — these are all authenticated, so a redirect or a 401 is the expected answer."""
    with TestClient(app) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code != 404, (
        f"{path} is in the inventory but the app has no such route — the inventory is "
        "constructing paths that do not exist."
    )
