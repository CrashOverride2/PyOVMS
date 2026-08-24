"""
Fold the Karto trip service's OpenAPI schema into this server's /docs.

Karto runs as its own process; the reverse proxy forwards /api/karto/ to it (see
doc/reverse proxy/nginx.conf). Operators still expect to find those endpoints in the
main server's documentation.
"""

import copy
import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Only paths below this prefix are merged. The export contains everything Karto
# serves, including its own /health — which this server also has. Filtering on the
# prefix the reverse proxy actually forwards keeps the fragment from describing, or
# silently replacing, a route that belongs to this application.
KARTO_PATH_PREFIX = "/api/karto/"

# Karto's component schemas are renamed on the way in. Several names are bound to
# collide (FastAPI generates HTTPValidationError and ValidationError in both
# services), and a collision would silently redefine one service's model with the
# other's shape. Renaming is unconditional rather than on-collision so the result
# does not depend on which models happen to exist here today.
SCHEMA_NAME_PREFIX = "Karto"

_FRAGMENT_PATH = Path(__file__).resolve().parents[2] / "doc" / "karto-openapi.json"

_TAG_NOTE = (
    "Served by the separate Karto trip service; the reverse proxy forwards "
    "these paths to it."
)


def load_fragment(path: Optional[Path] = None) -> Optional[dict]:
    """
    Read the exported Karto schema, or return None if it cannot be used.

    Never raises. This feeds the /docs endpoint, and documentation that is missing is
    a far better outcome than an admin page that returns 500.
    """
    fragment_path = path or _FRAGMENT_PATH
    try:
        with open(fragment_path, "r", encoding="utf-8") as handle:
            fragment = json.load(handle)
    except FileNotFoundError:
        logger.warning(
            "Karto API documentation not merged: %s is missing. Regenerate it with "
            "'python export_openapi.py' in the Karto checkout.", fragment_path
        )
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Karto API documentation not merged: %s is unreadable (%s).",
                       fragment_path, exc)
        return None

    if not isinstance(fragment, dict) or not isinstance(fragment.get("paths"), dict):
        logger.warning("Karto API documentation not merged: %s is not an OpenAPI document.",
                       fragment_path)
        return None
    return fragment


def _rewrite_schema_refs(node: Any, renames: dict[str, str]) -> Any:
    """Recursively repoint every $ref at the renamed component schemas."""
    if isinstance(node, dict):
        rewritten = {}
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                original = value.rsplit("/", 1)[-1]
                if value.startswith("#/components/schemas/") and original in renames:
                    rewritten[key] = f"#/components/schemas/{renames[original]}"
                    continue
            rewritten[key] = _rewrite_schema_refs(value, renames)
        return rewritten
    if isinstance(node, list):
        return [_rewrite_schema_refs(item, renames) for item in node]
    return node


def merge_karto_documentation(schema: dict, fragment: Optional[dict]) -> dict:
    """
    Merge the Karto fragment into `schema` in place and return it.

    Deliberately additive: an entry this server already defines always wins. A name
    that exists on both sides means the main application has grown a route or model
    of its own under that key, and quietly overwriting it would misdocument code that
    actually runs here in favour of code that does not.
    """
    if not fragment:
        return schema

    fragment = copy.deepcopy(fragment)

    fragment_schemas = fragment.get("components", {}).get("schemas", {})
    renames = {name: f"{SCHEMA_NAME_PREFIX}{name}" for name in fragment_schemas}

    schema.setdefault("paths", {})
    merged_paths, merged_tag_names = 0, set()

    for path, item in fragment["paths"].items():
        if not path.startswith(KARTO_PATH_PREFIX):
            continue
        if path in schema["paths"]:
            logger.warning(
                "Karto documentation: '%s' is already served by this application; "
                "keeping the local definition.", path
            )
            continue
        item = _rewrite_schema_refs(item, renames)
        schema["paths"][path] = item
        merged_paths += 1
        for operation in item.values():
            if isinstance(operation, dict):
                merged_tag_names.update(operation.get("tags", []))

    if not merged_paths:
        logger.warning("Karto documentation: the fragment contained no path under %s.",
                       KARTO_PATH_PREFIX)
        return schema

    components = schema.setdefault("components", {})
    target_schemas = components.setdefault("schemas", {})
    for name, definition in fragment_schemas.items():
        target_schemas.setdefault(renames[name], _rewrite_schema_refs(definition, renames))

    # Same header, same meaning on both services, so the existing scheme is reused
    # rather than duplicated under a prefixed name.
    fragment_security = fragment.get("components", {}).get("securitySchemes", {})
    if fragment_security:
        target_security = components.setdefault("securitySchemes", {})
        for name, definition in fragment_security.items():
            target_security.setdefault(name, definition)

    # Only tags the merged operations actually reference. Karto's export also
    # describes tags belonging to routes that were filtered out above.
    existing_tags = {tag.get("name") for tag in schema.get("tags", []) if isinstance(tag, dict)}
    for tag in fragment.get("tags", []):
        if not isinstance(tag, dict):
            continue
        name = tag.get("name")
        if name not in merged_tag_names or name in existing_tags:
            continue
        description = tag.get("description", "").strip()
        tag["description"] = f"{description} {_TAG_NOTE}".strip()
        schema.setdefault("tags", []).append(tag)

    logger.info("Karto API documentation merged: %d paths, %d schemas.",
                merged_paths, len(fragment_schemas))
    return schema
