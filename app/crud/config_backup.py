"""
Configuration snapshots of the OVMS Connect app — storage and retention.

One row per snapshot, the app's backup document as JSON text (see ConfigBackup in
app/models/db.py). The rules below decide what an upload *does*, and they are the
reason the columns and the index look the way they do:

* **Two kinds, two lifetimes.** An `auto` snapshot is one the app took on its own
  when it went to the background. Those roll: at most CONFIG_BACKUP_MAX_AUTO per
  (owner, device), the oldest evicted on every insert. A `manual` snapshot is one
  the user asked for, and it is *pinned* — never evicted, capped by refusing the
  next create with 409 instead. Silently deleting the snapshot someone took before
  an experiment would destroy exactly what the feature promises.

* **Per device.** The bucket for both the rolling window and the deduplication is
  (owner, kind, device_id). Two phones differ in at least a dashboard field, so a
  shared window would never deduplicate them against each other and they would
  fill it in alternation — the phone in the drawer, the one whose backup you want
  when the other breaks, ends up with no snapshot at all.

* **But only so many devices.** device_id is chosen by the client, and every new
  one opened a fresh window of MAX_AUTO rows past the minimum interval, so the
  only bound on a user's row count was the character quota — some 440,000 rows
  of minimal documents, all of them rendered by the profile page. At most
  CONFIG_BACKUP_MAX_DEVICES auto windows exist per user; when a new device would
  exceed that, the device whose newest auto row is oldest loses its auto rows.
  Pinned rows never take part: they are capped per user on their own.

* **Time, not clicks.** An auto upload younger than CONFIG_BACKUP_AUTO_COALESCE_
  MINUTES *replaces* the newest row of its bucket rather than adding one. Without
  this a window of ten holds the last ten app switches of one evening of theme
  editing, not the last ten states over months.

* **The server deduplicates too.** An upload whose *content* digest equals the
  newest row of its bucket is answered with that row — which takes the upload's
  label, if it carries one, so a manual snapshot of unchanged content does not
  lose the name the user just typed — and reports 200. The digest is over the
  document without its `meta` (see content_digest): the app stamps every
  snapshot with a fresh `meta.createdAt`, so a digest of the stored text never
  matched two uploads of the same configuration, and a phone opened once a day
  filled the window with ten identical rows. The app compares the same kind of
  digest before it sends anything; this is the half a broken client cannot skip.

  **`created_at` is the date of the content, and a deduplicated upload leaves it
  alone.** It used to be refreshed, and the coalesce window is measured from it:
  a configuration that had been stable for a month but was confirmed by the app
  every day counted as an hour old, and the first real change after that month
  *replaced* the stable state instead of adding a row — exactly the snapshot
  someone wants back after a mistake, gone from the window.

* **Minimum interval.** An auto upload of *unchanged* content, under the device
  name already stored, arriving within CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS
  of the newest row is answered with that row without writing anything, not
  even a label — the cheap guard against a dirty flag that never clears.
  Changed content is never throttled: it used to be, answered 200, and the app
  cleared its dirty flag over a change no snapshot held. Nor is a renamed
  device: the app sends a rename as one upload of unchanged content and never
  again. The router has already hashed the document by the time it gets here,
  so comparing the digest costs nothing.

* **One writer per user.** store_backup() and promote_to_manual() lock the
  owner's users row for the transaction (`SELECT ... FOR UPDATE`; a no-op on
  SQLite, which serialises writers anyway). The caps and the quota are
  read-check-write, and without the lock N concurrent uploads passed the check
  together and overshot by N-1 rows or N payloads.

Every setting is read at call time, so a test (or an operator) can change it
without re-importing this module.
"""

import datetime
import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.config import settings
from app.models.db import ConfigBackup, User

logger = logging.getLogger(__name__)

KIND_AUTO = "auto"
KIND_MANUAL = "manual"
KINDS = frozenset({KIND_AUTO, KIND_MANUAL})


class StoreOutcome(str, Enum):
    """What store_backup() did. Only CREATED is a new row; the router maps the rest
    to 200, and the app treats all four alike (its dirty flag clears) — which is
    why none of the three may leave the uploaded content unstored: THROTTLED and
    DEDUPLICATED both mean the newest row already holds it."""

    CREATED = "created"
    THROTTLED = "throttled"
    DEDUPLICATED = "deduplicated"
    COALESCED = "coalesced"


class ManualLimitReached(Exception):
    """CONFIG_BACKUP_MAX_MANUAL pinned snapshots already exist for this user."""


class StorageQuotaExceeded(Exception):
    """Storing this snapshot would take the user over CONFIG_BACKUP_MAX_TOTAL_CHARS_PER_USER."""


# The columns a listing returns — everything but the payload. The order is part of
# the contract with the UI template and the API model, which read by attribute.
SUMMARY_COLUMNS = (
    ConfigBackup.id,
    ConfigBackup.kind,
    ConfigBackup.label,
    ConfigBackup.device_id,
    ConfigBackup.device_name,
    ConfigBackup.app_version,
    ConfigBackup.platform,
    ConfigBackup.schema_version,
    ConfigBackup.stored_chars,
    ConfigBackup.created_at,
)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _as_utc(value: datetime.datetime) -> datetime.datetime:
    """SQLite and MySQL read the column back naive; every value stored is UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def content_digest(document: dict) -> str:
    """sha256 over the document without its `meta`.

    `meta.createdAt` changes on every collect, so a digest of the stored text is
    different for every upload of the same configuration — past the coalesce
    window each would have been a new row. The rest is serialised canonically
    (sorted keys, no whitespace), so neither key order nor the client's
    formatting takes part in the comparison."""
    content = {key: value for key, value in document.items() if key != "meta"}
    text = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bucket(query, owner_id: int, kind: str, device_id: Optional[str]):
    query = query.filter(ConfigBackup.owner_id == owner_id, ConfigBackup.kind == kind)
    if device_id is None:
        return query.filter(ConfigBackup.device_id.is_(None))
    return query.filter(ConfigBackup.device_id == device_id)


def _lock_owner(db: Session, owner_id: int) -> None:
    """Serialise the writers of one user for the rest of the transaction.

    Every cap here is checked with a read and enforced with a write; two requests
    in flight together both pass the read. A row lock on the owner is the cheapest
    fence there is — the row is committed at the end anyway — and it is dialect
    neutral: PostgreSQL and MySQL emit FOR UPDATE, SQLite drops it and has one
    writer per database regardless (tests/test_cross_dialect_sql.py checks both)."""
    db.query(User.id).filter(User.id == owner_id).with_for_update().first()


def list_backups(db: Session, owner_id: int):
    """Every snapshot of a user, newest first, without the payload."""
    return (
        db.query(ConfigBackup)
        .with_entities(*SUMMARY_COLUMNS)
        .filter(ConfigBackup.owner_id == owner_id)
        .order_by(ConfigBackup.created_at.desc(), ConfigBackup.id.desc())
        .all()
    )


def get_backup(db: Session, owner_id: int, backup_id: int) -> Optional[ConfigBackup]:
    """A snapshot by id, scoped to its owner: another user's id reads as absent."""
    return (
        db.query(ConfigBackup)
        .filter(ConfigBackup.id == backup_id, ConfigBackup.owner_id == owner_id)
        .first()
    )


def newest_for_kind_and_device(
    db: Session, owner_id: int, kind: str, device_id: Optional[str]
) -> Optional[ConfigBackup]:
    return (
        _bucket(db.query(ConfigBackup), owner_id, kind, device_id)
        .order_by(ConfigBackup.created_at.desc(), ConfigBackup.id.desc())
        .first()
    )


def count_by_kind(db: Session, owner_id: int, kind: str, device_id: Optional[str] = None,
                  *, any_device: bool = True) -> int:
    """Rows of one kind. With any_device (the default) the count spans every device —
    that is the manual cap, which is per user; pass any_device=False for one bucket."""
    query = db.query(func.count(ConfigBackup.id))
    if any_device:
        query = query.filter(ConfigBackup.owner_id == owner_id, ConfigBackup.kind == kind)
    else:
        query = _bucket(query, owner_id, kind, device_id)
    return int(query.scalar() or 0)


def total_stored_chars(db: Session, owner_id: int) -> int:
    total = (
        db.query(func.coalesce(func.sum(ConfigBackup.stored_chars), 0))
        .filter(ConfigBackup.owner_id == owner_id)
        .scalar()
    )
    return int(total or 0)


def stale_auto_ids_query(db: Session, owner_id: int, device_id: Optional[str]):
    """The auto rows of one bucket beyond the window, oldest last.

    Split out so tests/test_cross_dialect_sql.py can compile it for every backend:
    an OFFSET without a LIMIT is spelled differently across the three."""
    return (
        _bucket(db.query(ConfigBackup.id), owner_id, KIND_AUTO, device_id)
        .order_by(ConfigBackup.created_at.desc(), ConfigBackup.id.desc())
        .offset(settings.CONFIG_BACKUP_MAX_AUTO)
    )


def _evict_oldest_auto(db: Session, owner_id: int, device_id: Optional[str]) -> int:
    stale_ids = [row_id for (row_id,) in stale_auto_ids_query(db, owner_id, device_id).all()]
    if not stale_ids:
        return 0
    db.query(ConfigBackup).filter(ConfigBackup.id.in_(stale_ids)).delete(
        synchronize_session=False
    )
    logger.info(
        "Config backups: user %d device %s exceeded %d auto snapshots; dropped the %d oldest.",
        owner_id, device_id or "-", settings.CONFIG_BACKUP_MAX_AUTO, len(stale_ids),
    )
    return len(stale_ids)


def auto_windows_by_staleness_query(db: Session, owner_id: int):
    """(device_id, newest created_at) of every auto window of a user, the window
    whose newest row is oldest first. Split out for tests/test_cross_dialect_sql.py
    like stale_auto_ids_query: it orders by an aggregate."""
    newest = func.max(ConfigBackup.created_at)
    return (
        db.query(ConfigBackup.device_id, newest)
        .filter(ConfigBackup.owner_id == owner_id, ConfigBackup.kind == KIND_AUTO)
        .group_by(ConfigBackup.device_id)
        .order_by(newest.asc())
    )


def _make_room_for_device(db: Session, owner_id: int, device_id: Optional[str]) -> int:
    """Before an auto row opens a window for a device this user has none for:
    drop the auto rows of the stalest windows until one more fits under
    CONFIG_BACKUP_MAX_DEVICES. A device that already has a window costs nothing,
    so a fleet of real phones re-uploading never evicts one another; only a new
    id does, and only the device nobody has heard from the longest."""
    windows = [device for (device, _) in auto_windows_by_staleness_query(db, owner_id).all()]
    if device_id in windows:
        return 0
    excess = len(windows) - settings.CONFIG_BACKUP_MAX_DEVICES + 1
    if excess <= 0:
        return 0
    dropped = 0
    for stale in windows[:excess]:
        dropped += _bucket(db.query(ConfigBackup), owner_id, KIND_AUTO, stale).delete(
            synchronize_session=False
        )
    logger.info(
        "Config backups: user %d would exceed %d devices with auto snapshots; dropped "
        "the %d auto snapshot(s) of the %d stalest.",
        owner_id, settings.CONFIG_BACKUP_MAX_DEVICES, dropped, excess,
    )
    return dropped


def _check_quota(db: Session, owner_id: int, delta_chars: int) -> None:
    if total_stored_chars(db, owner_id) + delta_chars > settings.CONFIG_BACKUP_MAX_TOTAL_CHARS_PER_USER:
        raise StorageQuotaExceeded()


def store_backup(
    db: Session,
    owner_id: int,
    *,
    kind: str,
    payload: str,
    device_id: Optional[str],
    device_name: Optional[str],
    label: Optional[str],
    app_version: Optional[str],
    platform: Optional[str],
    schema_version: int,
    digest: Optional[str] = None,
) -> tuple[ConfigBackup, StoreOutcome]:
    """
    Store a validated snapshot and say what happened to it.

    Minimum interval, deduplication and coalescing are checked against the same
    bucket, in that order — the cheapest first. Only a CREATED outcome adds a row;
    it is preceded by making room for a new device (auto) and followed by eviction
    (auto) and the quota check, and a quota failure rolls the whole thing back so a
    413 leaves the table exactly as it was.

    `digest` is content_digest() of the parsed document; the router passes it so
    the text is parsed once. Left out, it is computed here.

    The payload is never logged; only its digest prefix and size are.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown backup kind {kind!r}")

    _lock_owner(db, owner_id)
    now = _now()
    if digest is None:
        digest = content_digest(json.loads(payload))
    newest = newest_for_kind_and_device(db, owner_id, kind, device_id)
    age = (now - _as_utc(newest.created_at)) if newest is not None else None
    unchanged = newest is not None and newest.payload_sha256 == digest

    if kind == KIND_AUTO and unchanged and (device_name is None or newest.device_name == device_name):
        # The name is part of "unchanged": the app forgets its digest on a rename so
        # that exactly one upload follows, and this path writes nothing — swallowing
        # that upload would lose the rename until the next real change.
        if age < datetime.timedelta(seconds=settings.CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS):
            return newest, StoreOutcome.THROTTLED

    if unchanged:
        # created_at stays: it is the date of this content, and the coalesce window
        # below is measured from it (see the module docstring).
        if label is not None:
            newest.label = label
        _adopt_device_name(db, owner_id, device_id, device_name)
        db.commit()
        db.refresh(newest)
        logger.info("Config backup for user %d: unchanged (sha %s), row %d kept.",
                    owner_id, digest[:8], newest.id)
        return newest, StoreOutcome.DEDUPLICATED

    coalesce = datetime.timedelta(minutes=settings.CONFIG_BACKUP_AUTO_COALESCE_MINUTES)
    if kind == KIND_AUTO and age is not None and coalesce > datetime.timedelta(0) and age < coalesce:
        _check_quota(db, owner_id, len(payload) - newest.stored_chars)
        newest.payload = payload
        newest.stored_chars = len(payload)
        newest.payload_sha256 = digest
        newest.created_at = now
        if device_name is not None:
            newest.device_name = device_name
        newest.app_version = app_version
        newest.platform = platform
        newest.schema_version = schema_version
        if label is not None:
            newest.label = label
        _adopt_device_name(db, owner_id, device_id, device_name)
        db.commit()
        db.refresh(newest)
        logger.info("Config backup for user %d: replaced row %d (sha %s, %d chars).",
                    owner_id, newest.id, digest[:8], len(payload))
        return newest, StoreOutcome.COALESCED

    if kind == KIND_MANUAL and count_by_kind(db, owner_id, KIND_MANUAL) >= settings.CONFIG_BACKUP_MAX_MANUAL:
        raise ManualLimitReached()
    if kind == KIND_AUTO:
        _make_room_for_device(db, owner_id, device_id)

    row = ConfigBackup(
        owner_id=owner_id,
        kind=kind,
        label=label,
        device_id=device_id,
        device_name=device_name,
        app_version=app_version,
        platform=platform,
        schema_version=schema_version,
        payload=payload,
        stored_chars=len(payload),
        payload_sha256=digest,
        created_at=now,
    )
    db.add(row)
    db.flush()
    _adopt_device_name(db, owner_id, device_id, device_name)
    if kind == KIND_AUTO:
        _evict_oldest_auto(db, owner_id, device_id)
    try:
        # The new row is flushed, so the total already includes it.
        _check_quota(db, owner_id, 0)
    except StorageQuotaExceeded:
        db.rollback()
        raise
    db.commit()
    db.refresh(row)
    logger.info("Config backup for user %d: stored row %d (%s, sha %s, %d chars).",
                owner_id, row.id, kind, digest[:8], len(payload))
    return row, StoreOutcome.CREATED


def _adopt_device_name(
    db: Session, owner_id: int, device_id: Optional[str], device_name: Optional[str]
) -> None:
    """A device renamed in the app renames its earlier rows too.

    The name travels with every upload but the rows already stored keep theirs, so
    without this one phone showed up as two devices on the profile page — the old
    name over the old rows, the new one over the new. Called on every path that
    writes anyway (deduplicated, coalesced, created); the throttled path stays a
    pure read."""
    if device_id is None or device_name is None:
        return
    db.query(ConfigBackup).filter(
        ConfigBackup.owner_id == owner_id,
        ConfigBackup.device_id == device_id,
        or_(ConfigBackup.device_name.is_(None), ConfigBackup.device_name != device_name),
    ).update({ConfigBackup.device_name: device_name}, synchronize_session=False)


@dataclass
class DeviceBackupGroup:
    """One device's rows as the profile page shows them: the pinned (manual) ones
    first, then the rolling automatic ones, each newest first. `suffix` is set only
    when another device of the same account carries the same name — the first
    characters of the device id, so two identical phones can be told apart without
    printing the whole hash."""

    device_id: Optional[str]
    name: Optional[str]
    platform: Optional[str]
    manual: List = field(default_factory=list)
    auto: List = field(default_factory=list)
    suffix: Optional[str] = None


def group_by_device(rows) -> List[DeviceBackupGroup]:
    """list_backups() rows (newest first) grouped per device, groups in the order
    of their newest row. Rows without a device id form one group of their own."""
    groups: dict = {}
    order: list = []
    for row in rows:
        group = groups.get(row.device_id)
        if group is None:
            group = DeviceBackupGroup(device_id=row.device_id, name=row.device_name, platform=row.platform)
            groups[row.device_id] = group
            order.append(row.device_id)
        (group.manual if row.kind == KIND_MANUAL else group.auto).append(row)
    result = [groups[key] for key in order]
    by_name: dict = {}
    for group in result:
        by_name.setdefault(group.name, []).append(group)
    for same_name in by_name.values():
        if len(same_name) > 1:
            for group in same_name:
                group.suffix = (group.device_id or "")[:4] or None
    return result


def promote_to_manual(db: Session, backup: ConfigBackup) -> ConfigBackup:
    """Pin an auto snapshot. The only transition there is: the reverse would let a
    client push a deliberate snapshot back into the rolling window."""
    if backup.kind == KIND_MANUAL:
        return backup
    _lock_owner(db, backup.owner_id)
    if count_by_kind(db, backup.owner_id, KIND_MANUAL) >= settings.CONFIG_BACKUP_MAX_MANUAL:
        raise ManualLimitReached()
    backup.kind = KIND_MANUAL
    db.commit()
    db.refresh(backup)
    return backup


def delete_backup(db: Session, owner_id: int, backup_id: int) -> bool:
    deleted = (
        db.query(ConfigBackup)
        .filter(ConfigBackup.id == backup_id, ConfigBackup.owner_id == owner_id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted > 0
