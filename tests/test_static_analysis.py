"""
Static guards for whole classes of defect, not individual bugs.

test_no_undefined_names is the one that matters most: three modules called
`security_manager.record_failure(...)` without importing the name. Every one of those
call sites is a brute-force counter, so six security-relevant paths raised NameError and
returned HTTP 500 instead of recording a failure — silently, because they only run when
someone is already doing something wrong. A single `ruff check --select F821` would have
caught all six, which is why this also lives in requirements-dev.txt.
"""

import ast
import builtins
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "app"

# Module-level dunders that are always present at runtime but are not builtins.
_MODULE_GLOBALS = {"__file__", "__name__", "__doc__", "__package__", "__spec__", "__loader__"}


def _bound_names(tree: ast.AST) -> set[str]:
    """Names bound anywhere in the module (deliberately flow-insensitive)."""
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.Global):
            bound.update(node.names)
        elif isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
    return bound


def _undefined_names(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(), str(path))
    bound = _bound_names(tree) | set(dir(builtins)) | _MODULE_GLOBALS
    return sorted({
        f"{path.relative_to(REPO_ROOT)}:{node.lineno} {node.id}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in bound
    })


ALL_APP_MODULES = sorted(APP_DIR.rglob("*.py"))


@pytest.mark.parametrize("path", ALL_APP_MODULES, ids=lambda p: str(p.relative_to(APP_DIR)))
def test_no_undefined_names(path):
    """Catches the missing-import class of bug that killed six rate-limit call sites."""
    assert _undefined_names(path) == []


def test_security_manager_is_imported_wherever_it_is_used():
    """The specific regression, asserted by name so the failure message is obvious."""
    offenders = []
    for path in ALL_APP_MODULES:
        source = path.read_text()
        if "security_manager." not in source:
            continue
        if path.name == "security_manager.py":
            continue
        if "import security_manager" not in source:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == [], f"security_manager used without being imported in: {offenders}"


def test_autoprovision_api_requires_admin():
    """
    H-5: the UI guards AP-profile creation with require_admin_user_from_cookie; the API
    guarded it with require_active_api_user, and the ownership check only fires when the
    target vehicle already exists — so any user could pre-seed credentials for a vehicle
    id nobody had registered yet.
    """
    source = (APP_DIR / "routers" / "api" / "main.py").read_text()
    marker = '@router.post("/autoprovision_profiles"'
    start = source.index(marker)
    decorator_and_signature = source[start:start + 900]
    assert "require_admin_api_user" in decorator_and_signature
    assert "dependencies=[Depends(require_active_api_user)]" not in decorator_and_signature


def test_logout_clears_both_cookie_variants():
    """
    H-12: _get_access_token() accepts '__Host-access_token' or 'access_token'. Clearing
    only one leaves the other authenticating the next request.
    """
    source = (APP_DIR / "routers" / "ui" / "auth.py").read_text()

    # Located by AST rather than by slicing on "async def ui_logout_route". The string
    # search silently stopped matching the day the route became a plain `def` (routes
    # that never await belong in the threadpool, not on the event loop), and a test whose
    # subject can vanish under a rename is not testing anything.
    logout_fn = next(
        (
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "ui_logout_route"
        ),
        None,
    )
    assert logout_fn is not None, "ui_logout_route() is gone from ui/auth.py — update this test."

    joined = "\n".join(
        line
        for line in ast.unparse(logout_fn).splitlines()
        if "delete_cookie" in line or "key=" in line
    )
    assert "__Host-access_token" in joined, "secure cookie not cleared on logout"
    assert "access_token" in joined.replace("__Host-access_token", ""), (
        "legacy cookie survives logout and keeps authenticating the next request"
    )


def test_unauthenticated_tcp_sockets_have_an_absolute_deadline():
    """
    H-4: the read timeout is per-read and restarts on every byte, and blank lines skip
    the auth handler entirely — so a peer sending '\\n' once a minute held a connection
    slot forever without ever counting as a failure.
    """
    source = (APP_DIR / "tcp_server.py").read_text()
    assert "connection_started_at" in source
    assert "_MAX_BLANK_LINES_BEFORE_AUTH" in source
    assert "TIMEOUT_TCP_INITIAL_AUTH" in source


def test_client_ip_is_not_reparsed_from_forwarded_headers():
    """
    Regression guard for the previously fixed X-Forwarded-For handling: a second XFF
    implementation next to uvicorn's can only ever be wrong, and taking the leftmost
    entry lets a client choose its own rate-limit identity.
    """
    source = (APP_DIR / "dependencies.py").read_text()
    get_client_ip = source[source.index("async def get_client_ip"):]
    body = get_client_ip[:get_client_ip.index("async def", 10)] if "async def" in get_client_ip[10:] else get_client_ip
    assert "X-Forwarded-For" not in body.split('"""')[-1], "get_client_ip must not parse XFF itself"


def test_the_migration_history_has_exactly_one_head():
    """
    Two migrations naming the same predecessor produce two heads, and
    `alembic upgrade head` then refuses to run at all — bootstrap.run_migrations()
    fails and the server does not start. It is a mistake with no symptom until
    deployment, because a developer whose database is already current never runs the
    upgrade that would reveal it.
    """
    import re

    versions = REPO_ROOT / "alembic" / "versions"
    revisions, parents = set(), set()

    for path in versions.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        revision = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)", source, re.M)
        parent = re.search(r"^down_revision[^=]*=\s*['\"]?([^'\"\n]+)", source, re.M)
        if revision:
            revisions.add(revision.group(1))
        if parent and parent.group(1).strip() not in ("None", ""):
            parents.add(parent.group(1).strip())

    heads = revisions - parents
    assert len(heads) == 1, f"alembic has {len(heads)} heads, expected 1: {sorted(heads)}"
