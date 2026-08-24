"""
The Karto API is documented from an exported schema, not from a copy of its code.

app/services/karto/ used to hold a full copy of Karto's routers so FastAPI had route
objects to describe in /docs. It was dead code in any correct deployment — the
reverse proxy sends /api/karto/ to the separate service — and it had already drifted:
its /maps handler still parsed the vehicle id out of the filename after the real
service had replaced that with a database lookup. What kept the drift harmless was a
stub crud module returning False, one edit away from failing open.

These tests bind the replacement: the fragment is merged, the merge is additive, and
the package stays gone.
"""

import copy
import json
from pathlib import Path

import pytest

from app.services.karto_docs import (
    KARTO_PATH_PREFIX,
    load_fragment,
    merge_karto_documentation,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def fragment() -> dict:
    loaded = load_fragment()
    assert loaded is not None, "doc/karto-openapi.json is missing or unreadable"
    return loaded


@pytest.fixture
def base_schema() -> dict:
    """The real schema of this application, before anything is merged into it."""
    from app.main import app

    return copy.deepcopy(app.openapi())


def test_stub_package_is_gone():
    """
    The executable copy must not come back. Documentation is not a reason to carry
    another service's authorization code in this repository.
    """
    assert not (REPO_ROOT / "app" / "services" / "karto").exists()

    with pytest.raises(ModuleNotFoundError):
        __import__("app.services.karto.api")


def test_application_serves_no_karto_route(base_schema):
    """
    Documentation only. A route answering here would shadow the proxy target and,
    since this process has no Karto database, answer it wrongly.
    """
    from app.main import app

    served = [r.path for r in app.routes if getattr(r, "path", "").startswith(KARTO_PATH_PREFIX)]
    assert served == []
    assert not any(p.startswith(KARTO_PATH_PREFIX) for p in base_schema["paths"])


def test_fragment_documents_the_karto_api(fragment):
    karto_paths = [p for p in fragment["paths"] if p.startswith(KARTO_PATH_PREFIX)]
    assert len(karto_paths) >= 8, "export looks truncated"


def test_merge_adds_only_prefixed_paths(base_schema, fragment):
    """
    The export also contains Karto's own /health, and this server has one too. Merging
    by prefix is what keeps the fragment from redefining a local route.
    """
    assert "/health" in fragment["paths"], "fixture assumption: the export contains /health"
    local_health = copy.deepcopy(base_schema["paths"]["/health"])

    merged = merge_karto_documentation(base_schema, fragment)

    added = [p for p in merged["paths"] if p.startswith(KARTO_PATH_PREFIX)]
    assert len(added) >= 8
    assert merged["paths"]["/health"] == local_health


def test_local_path_definition_wins(base_schema, fragment):
    """A path this application really serves must never be described by the fragment."""
    contested = next(p for p in fragment["paths"] if p.startswith(KARTO_PATH_PREFIX))
    sentinel = {"get": {"summary": "served locally", "responses": {}}}
    base_schema["paths"][contested] = copy.deepcopy(sentinel)

    merged = merge_karto_documentation(base_schema, fragment)

    assert merged["paths"][contested] == sentinel


def test_component_names_are_prefixed_and_do_not_clobber(base_schema, fragment):
    """
    Both services generate HTTPValidationError. Renaming on the way in means neither
    definition can displace the other.

    Asserted against literal names rather than SCHEMA_NAME_PREFIX: reading the
    constant back makes the assertion true for any value of it, including "", which
    is precisely the broken configuration. Without a prefix the merge keeps the local
    definition and drops Karto's, so every $ref still resolves and the only symptom
    is a Karto model documented with this server's shape.
    """
    fragment_schemas = fragment["components"]["schemas"]
    assert "HTTPValidationError" in fragment_schemas, "fixture assumption: a colliding name exists"
    before = copy.deepcopy(base_schema["components"]["schemas"])
    assert "HTTPValidationError" in before, "fixture assumption: this server defines it too"

    merged = merge_karto_documentation(base_schema, fragment)
    after = merged["components"]["schemas"]

    for name, definition in before.items():
        assert after[name] == definition, f"merge overwrote local schema '{name}'"

    for name, definition in fragment_schemas.items():
        prefixed = f"Karto{name}"
        assert prefixed in after, f"Karto model '{name}' was dropped instead of prefixed"
        assert after[prefixed] == _rewrite_for_comparison(definition, fragment_schemas), (
            f"'{prefixed}' does not carry Karto's definition"
        )


def _rewrite_for_comparison(definition: dict, fragment_schemas: dict) -> dict:
    """Karto's definition with its internal $refs repointed, as the merge stores it."""
    serialised = json.dumps(definition)
    for name in sorted(fragment_schemas, key=len, reverse=True):
        serialised = serialised.replace(
            f'"#/components/schemas/{name}"', f'"#/components/schemas/Karto{name}"'
        )
    return json.loads(serialised)


def test_every_reference_resolves_after_merge(base_schema, fragment):
    """
    The guard that makes the renaming safe: a rewrite that misses a $ref produces a
    schema that renders as a broken page rather than failing loudly, so assert it
    directly over the whole merged document.
    """
    merged = merge_karto_documentation(base_schema, fragment)
    defined = set(merged["components"]["schemas"])

    def refs(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str) and value.startswith("#/components/schemas/"):
                    yield value.rsplit("/", 1)[-1]
                else:
                    yield from refs(value)
        elif isinstance(node, list):
            for item in node:
                yield from refs(item)

    dangling = sorted({name for name in refs(merged) if name not in defined})
    assert dangling == [], f"unresolved $ref after merge: {dangling}"


def test_merged_document_is_serialisable(base_schema, fragment):
    """/openapi.json returns this verbatim; a non-JSON value would 500 the docs page."""
    json.dumps(merge_karto_documentation(base_schema, fragment))


def test_missing_fragment_is_a_no_op(base_schema, tmp_path):
    """
    A checkout without the export, or with a corrupt one, must still serve /docs.
    Documentation is not worth an exception on an authenticated admin page.
    """
    assert load_fragment(tmp_path / "does-not-exist.json") is None

    corrupt = tmp_path / "karto-openapi.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert load_fragment(corrupt) is None

    not_openapi = tmp_path / "other.json"
    not_openapi.write_text('{"hello": "world"}', encoding="utf-8")
    assert load_fragment(not_openapi) is None

    unchanged = copy.deepcopy(base_schema)
    assert merge_karto_documentation(base_schema, None) == unchanged


def test_docs_endpoint_actually_merges_when_karto_is_enabled(monkeypatch):
    """
    Binds the wiring, not just the merge function.

    Everything above calls merge_karto_documentation() directly, which says nothing
    about whether custom_openapi() ever calls it. A correct helper that no code path
    reaches is the failure this repository has already shipped twice — the tojson
    override and the JWT key guard that could not fire.
    """
    from app.config import settings
    from app.main import app

    monkeypatch.setattr(settings, "ENABLE_KARTO_TRIP_TRACKING", True)
    monkeypatch.setattr(app, "openapi_schema", None)

    schema = app.openapi()

    assert any(p.startswith(KARTO_PATH_PREFIX) for p in schema["paths"]), (
        "custom_openapi() did not merge the Karto fragment"
    )
    assert "KartoTripDetail" in schema["components"]["schemas"]


def test_docs_endpoint_omits_karto_when_disabled(monkeypatch):
    """The flag has to work in both directions, or it is not a flag."""
    from app.config import settings
    from app.main import app

    monkeypatch.setattr(settings, "ENABLE_KARTO_TRIP_TRACKING", False)
    monkeypatch.setattr(app, "openapi_schema", None)

    schema = app.openapi()

    assert not any(p.startswith(KARTO_PATH_PREFIX) for p in schema["paths"])


def test_merge_does_not_mutate_the_fragment(base_schema, fragment):
    """
    The fragment is cached at module scope here and load_fragment() may be called once
    per process; a merge that edited it in place would corrupt the next merge.
    """
    before = copy.deepcopy(fragment)
    merge_karto_documentation(base_schema, fragment)
    assert fragment == before
