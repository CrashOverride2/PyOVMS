"""
Configuration backups of the OVMS Connect app — /api/v1/config-backups.

The app stores snapshots of its own settings here so a reinstall can be set up from
the account. Everything the server does with a snapshot is decided in
app/crud/config_backup.py; this module is the boundary, and the boundary has two
jobs that are not obvious from the routes:

* **A payload must not carry a credential.** The app's allowlist is what keeps
  passwords, API keys and WiFi secrets out of the document, and this endpoint is
  the honest counterpart: every object *key* in the document is checked against a
  denylist (never the values — a command named "unlock password" is not a leak)
  and a match is refused with 422. The document is stored as plain text on the
  strength of this check, so it is not optional and it is not advisory.

* **A payload must not carry an image.** Images stay in the app's local ZIP
  export; a document with an `assets` key or an `asset:<id>` reference is a
  broken client, refused rather than stored. The server never decodes an image
  and must never start to.

* **A payload must fit the walks that check it.** Both checks recurse over the
  document, and so does `json.loads` itself; a few hundred brackets in a few
  hundred bytes turn any of them into a RecursionError — a 500, and a hundred
  kilobytes of traceback in the log per request. The depth is therefore measured
  first, without recursion, and anything past MAX_DOCUMENT_DEPTH is refused with
  422. A real document is about eight levels deep.

* **A payload must be text the rest of the server can encode.** JSON allows the
  escape `\\ud800` — half of a surrogate pair — and Python's parser turns it into
  a str that UTF-8 cannot encode. Everything downstream encodes: the content
  digest, the database driver, even the 422 that names a denied key. Each of
  those was a 500. The parsed document is walked for such strings before any
  other check (has_unencodable_text, iterative like the depth walk). The payload
  *text* alone is not enough to check: the escape is seven clean ASCII bytes
  until it is parsed. At the outer level — the escape in `payload`, `label` or
  `device_name` of the request body itself — pydantic's own str validation
  refuses it first (`string_unicode`), which is why the 422 handler in app/main.py
  must never echo the offending input.

Ownership is strict: another user's row answers 404, for administrators too. A
snapshot is someone's themes, vehicle names and commands, and reading those helps
nobody; 404 also confirms nothing about which ids exist.

`CONFIG_BACKUP_ENABLED=false` refuses everything that would create, change or hand
out a snapshot (403) and answers the listing with `enabled: false`, which is how
the app learns to stop offering the feature. Deleting stays open, here and on the
profile page: an operator switching the feature off must not strand anyone's data.

All handlers are plain `def` — every one touches the database, and
tests/test_routes_do_not_block_the_event_loop.py enforces it.
"""

import json
import logging
import re
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app import crud
from app.config import settings
from app.crud import config_backup as crud_backup
from app.database import get_db
from app.dependencies import api_key_header, require_active_api_user
from app.models import db as models_db
from app.utils.timestamps import UtcDatetime

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/config-backups",
    tags=["Config Backups"],
    dependencies=[Depends(require_active_api_user)],
)

# --- the credential denylist ------------------------------------------------------
#
# Shared with the app: doc/config-backup-plan.md in the OVMS Connect repository is
# the one place both halves are written down, and the app's
# config_backup_secrets_test.dart checks the payload it produces against the same
# rule. A new app setting whose name matches this is a deliberate decision on both
# sides, because an older server would refuse it with 422.
#
# Keys are compared case-insensitively; the stems match with `_` and `-` removed,
# so `api_key`, `apiKey` and `api-key` are one thing.
DENIED_KEY_NAMES = frozenset({
    "wifiappassword", "wifiapssid", "moduleapikey", "mqtt_password", "ovms_api_key",
    "apikey", "api_key", "password", "hashed_password", "secret", "token",
})
DENIED_KEY_STEMS = ("password", "passwd", "secret", "token", "apikey", "credential")

DEVICE_ID_PATTERN = re.compile(r"[0-9a-f]{1,32}")

# The deepest path the app writes is vehicles[i].customLayoutConfig.dataPoints[j].
# <field>, eight levels. The limit is what keeps find_denied_key,
# carries_image_reference and json.dumps in content_digest clear of the
# interpreter's recursion limit, which a client reaches with a few hundred brackets.
MAX_DOCUMENT_DEPTH = 32

# schema_version is an Integer column: a 32-bit value on PostgreSQL and MySQL, and
# SQLite refuses anything past 64 bits with an OverflowError at insert time. The
# app's own schema version is a small number; the bound only turns a 500 into 422.
MAX_SCHEMA_VERSION = 2**31 - 1

DETAIL_MANUAL_LIMIT = "manual_backup_limit_reached"
DETAIL_QUOTA = "storage_quota_exceeded"
DETAIL_DISABLED = "config_backups_disabled"
DETAIL_TOO_DEEP = "payload is nested too deeply"
DETAIL_NOT_UNICODE = "must not contain unpaired surrogate escapes"


def is_denied_key(key: str) -> bool:
    folded = key.lower()
    if folded in DENIED_KEY_NAMES:
        return True
    compact = folded.replace("_", "").replace("-", "")
    return any(stem in compact for stem in DENIED_KEY_STEMS)


def document_depth(node: Any) -> int:
    """Nesting depth of a parsed document — 1 for a flat object, 2 for an object
    holding an object — measured with an explicit stack, because this is the
    check that has to survive a document built to exhaust the recursive ones."""
    deepest = 0
    stack = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        deepest = max(deepest, depth)
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return deepest


def is_encodable(value: str) -> bool:
    """False for a str that UTF-8 cannot represent — a lone surrogate, which JSON
    lets a client spell as `\\ud800` and Python's parser accepts."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def has_unencodable_text(node: Any) -> bool:
    """True if any key or string value in the document fails is_encodable().
    Iterative, for the same reason document_depth is; runs after it, so the
    document is already known to be of sane depth."""
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            if not is_encodable(current):
                return True
        elif isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return False


def find_denied_key(node: Any, path: str = "$") -> Optional[str]:
    """The path of the first object key that looks like a credential, or None."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}"
            if isinstance(key, str) and is_denied_key(key):
                return here
            found = find_denied_key(value, here)
            if found:
                return found
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found = find_denied_key(item, f"{path}[{index}]")
            if found:
                return found
    return None


def carries_image_reference(node: Any) -> bool:
    """True for a string value of the form `asset:<id>` anywhere in the document."""
    if isinstance(node, str):
        return node.startswith("asset:")
    if isinstance(node, dict):
        return any(carries_image_reference(v) for v in node.values())
    if isinstance(node, list):
        return any(carries_image_reference(v) for v in node)
    return False


# --- request and response models --------------------------------------------------

def _clean_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    candidate = value.strip()
    return candidate or None


class ConfigBackupCreate(BaseModel):
    kind: str = Field(..., description="'auto' for a background snapshot, 'manual' for one the user asked for.")
    label: Optional[str] = Field(None, max_length=100)
    device_id: Optional[str] = Field(None, max_length=32)
    device_name: Optional[str] = Field(None, max_length=64)
    # max_length first and cheapest: on plain text it is an honest statement about
    # what the column will hold, with no decompression behind it.
    payload: str = Field(..., min_length=2, max_length=settings.CONFIG_BACKUP_MAX_PAYLOAD_CHARS)

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        if v not in crud_backup.KINDS:
            raise ValueError("kind must be 'auto' or 'manual'")
        return v

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not DEVICE_ID_PATTERN.fullmatch(v):
            raise ValueError("device_id must be 1–32 lowercase hex characters")
        return v

    @field_validator("label", "device_name")
    @classmethod
    def validate_free_text(cls, v: Optional[str]) -> Optional[str]:
        v = _clean_optional(v)
        if v is not None and any(ch in v for ch in "\r\n\x00"):
            raise ValueError("must not contain line breaks")
        return v


class ConfigBackupPin(BaseModel):
    kind: str

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        # The only transition offered. manual -> auto would let a client push a
        # deliberate snapshot back into the rolling window, where it can be evicted.
        if v != crud_backup.KIND_MANUAL:
            raise ValueError("a backup can only be pinned (kind 'manual')")
        return v


class ConfigBackupSummary(BaseModel):
    id: int
    kind: str
    label: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    app_version: Optional[str] = None
    platform: Optional[str] = None
    schema_version: int
    stored_chars: int
    created_at: UtcDatetime

    class Config:
        from_attributes = True


class ConfigBackupList(BaseModel):
    enabled: bool
    items: List[ConfigBackupSummary]


class ConfigBackupQuota(BaseModel):
    stored_chars: int
    max_stored_chars: int
    auto_used: int
    auto_max: int
    manual_used: int
    manual_max: int


# --- helpers ----------------------------------------------------------------------

def _require_enabled() -> None:
    if not settings.CONFIG_BACKUP_ENABLED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=DETAIL_DISABLED)


def _device_name_from_key(db: Session, api_key_value: Optional[str]) -> Optional[str]:
    """The device the request's key was provisioned for, from its `device-<name>`."""
    if not api_key_value:
        return None
    key_row = crud.apikey.get_api_key_by_raw_key(db, api_key_value)
    prefix = crud.apikey.DEVICE_KEY_NAME_PREFIX
    if key_row and key_row.name and key_row.name.startswith(prefix):
        return key_row.name[len(prefix):][:64] or None
    return None


def _validated_document(payload: str) -> dict:
    """The parsed document, after the checks that make plain-text storage safe."""
    try:
        document = json.loads(payload)
    except RecursionError:
        # The parser itself recurses once per bracket; past the interpreter's
        # limit it gives up before the depth below can be measured.
        raise HTTPException(status_code=422, detail=DETAIL_TOO_DEEP)
    except ValueError:
        raise HTTPException(status_code=422, detail="payload is not valid JSON")
    if not isinstance(document, dict):
        raise HTTPException(status_code=422, detail="payload must be a JSON object")
    if document_depth(document) > MAX_DOCUMENT_DEPTH:
        raise HTTPException(status_code=422, detail=DETAIL_TOO_DEEP)
    # Before the denied-key walk: its 422 quotes the key, and a key that cannot be
    # encoded would turn that answer itself into a 500.
    if has_unencodable_text(document):
        raise HTTPException(status_code=422, detail=f"payload {DETAIL_NOT_UNICODE}")

    schema_version = document.get("schemaVersion")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) \
            or not 1 <= schema_version <= MAX_SCHEMA_VERSION:
        raise HTTPException(
            status_code=422,
            detail=f"payload.schemaVersion must be an integer between 1 and {MAX_SCHEMA_VERSION}",
        )

    denied = find_denied_key(document)
    if denied:
        # The key path is named, the value never is.
        raise HTTPException(
            status_code=422,
            detail=f"payload must not contain credentials (key {denied})",
        )
    if "assets" in document or carries_image_reference(document):
        raise HTTPException(
            status_code=422,
            detail="payload must not contain images; server backups carry settings only",
        )
    return document


def _meta_string(meta: Any, key: str, limit: int, *, truncate: bool = True) -> Optional[str]:
    """A free-text field of the document's `meta`, under the same rule as the
    body's own fields: no line breaks, because the value ends up in a listing
    and in a download file name. Encodability was checked on the whole document
    by _validated_document(). Over `limit`, the value is cut — or, with
    truncate=False, refused: an identifier that is silently shortened names a
    different thing."""
    if not isinstance(meta, dict):
        return None
    value = meta.get(key)
    if not isinstance(value, str):
        return None
    if any(ch in value for ch in "\r\n\x00"):
        raise HTTPException(status_code=422, detail=f"meta.{key} must not contain line breaks")
    value = value.strip()
    if len(value) > limit:
        if not truncate:
            raise HTTPException(status_code=422, detail=f"meta.{key} must be at most {limit} characters")
        value = value[:limit]
    return value or None


def _get_owned(db: Session, current_user: models_db.User, backup_id: int) -> models_db.ConfigBackup:
    row = crud_backup.get_backup(db, current_user.id, backup_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Backup not found")
    return row


# --- routes -----------------------------------------------------------------------
#
# /quota is declared before /{backup_id}: the path parameter is an int and would
# not match "quota" anyway, but the order is what a reader expects to have to check.

@router.get("/quota", response_model=ConfigBackupQuota)
def api_config_backup_quota(
    device_id: Optional[str] = Query(None, max_length=32),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
):
    _require_enabled()
    if device_id is not None and not DEVICE_ID_PATTERN.fullmatch(device_id):
        raise HTTPException(status_code=422, detail="device_id must be 1–32 lowercase hex characters")
    return ConfigBackupQuota(
        stored_chars=crud_backup.total_stored_chars(db, current_user.id),
        max_stored_chars=settings.CONFIG_BACKUP_MAX_TOTAL_CHARS_PER_USER,
        auto_used=crud_backup.count_by_kind(
            db, current_user.id, crud_backup.KIND_AUTO, device_id, any_device=device_id is None
        ),
        auto_max=settings.CONFIG_BACKUP_MAX_AUTO,
        manual_used=crud_backup.count_by_kind(db, current_user.id, crud_backup.KIND_MANUAL),
        manual_max=settings.CONFIG_BACKUP_MAX_MANUAL,
    )


@router.get("", response_model=ConfigBackupList)
def api_list_config_backups(
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
):
    """Metadata only — the payload of a snapshot is fetched by id."""
    if not settings.CONFIG_BACKUP_ENABLED:
        return ConfigBackupList(enabled=False, items=[])
    rows = crud_backup.list_backups(db, current_user.id)
    return ConfigBackupList(enabled=True, items=[ConfigBackupSummary.model_validate(r) for r in rows])


@router.post("", response_model=ConfigBackupSummary, status_code=status.HTTP_201_CREATED,
             responses={200: {"model": ConfigBackupSummary,
                              "description": "Unchanged, coalesced into, or throttled against the newest snapshot"},
                        409: {"description": "Manual snapshot limit reached"},
                        413: {"description": "Storage quota exceeded"}})
def api_create_config_backup(
    body: ConfigBackupCreate,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
    api_key_value: Optional[str] = Security(api_key_header),
):
    _require_enabled()
    document = _validated_document(body.payload)
    meta = document.get("meta")

    device_id = body.device_id
    if device_id is None:
        candidate = _meta_string(meta, "deviceId", 32, truncate=False)
        if candidate is not None:
            if not DEVICE_ID_PATTERN.fullmatch(candidate):
                raise HTTPException(status_code=422, detail="meta.deviceId must be 1–32 lowercase hex characters")
            device_id = candidate

    device_name = body.device_name or _meta_string(meta, "deviceName", 64) \
        or _device_name_from_key(db, api_key_value)
    label = body.label if body.label is not None else _meta_string(meta, "label", 100)

    try:
        row, outcome = crud_backup.store_backup(
            db,
            current_user.id,
            kind=body.kind,
            payload=body.payload,
            device_id=device_id,
            device_name=device_name,
            label=label,
            app_version=_meta_string(meta, "appVersion", 32),
            platform=_meta_string(meta, "platform", 16),
            schema_version=int(document["schemaVersion"]),
            digest=crud_backup.content_digest(document),
        )
    except crud_backup.ManualLimitReached:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=DETAIL_MANUAL_LIMIT)
    except crud_backup.StorageQuotaExceeded:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=DETAIL_QUOTA)

    summary = ConfigBackupSummary.model_validate(row)
    if outcome is crud_backup.StoreOutcome.CREATED:
        return summary
    # Three server-side decisions the client need not tell apart: the snapshot it
    # holds is represented, and its dirty flag may clear.
    return JSONResponse(status_code=status.HTTP_200_OK, content=summary.model_dump(mode="json"))


@router.patch("/{backup_id}", response_model=ConfigBackupSummary,
              responses={409: {"description": "Manual snapshot limit reached"}})
def api_pin_config_backup(
    backup_id: int,
    body: ConfigBackupPin,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
):
    """Pin an automatic snapshot so the rolling window cannot evict it."""
    _require_enabled()
    row = _get_owned(db, current_user, backup_id)
    try:
        row = crud_backup.promote_to_manual(db, row)
    except crud_backup.ManualLimitReached:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=DETAIL_MANUAL_LIMIT)
    return ConfigBackupSummary.model_validate(row)


@router.get("/{backup_id}")
def api_get_config_backup(
    backup_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
):
    """The stored document, byte for byte as it was uploaded."""
    _require_enabled()
    row = _get_owned(db, current_user, backup_id)
    return Response(content=row.payload, media_type="application/json")


@router.delete("/{backup_id}", status_code=status.HTTP_204_NO_CONTENT)
def api_delete_config_backup(
    backup_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
):
    # Deliberately not behind _require_enabled(): the kill switch stops snapshots
    # from being taken or handed out, never a user from removing their own.
    if not crud_backup.delete_backup(db, current_user.id, backup_id):
        raise HTTPException(status_code=404, detail="Backup not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
