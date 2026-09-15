"""
Configuration backups are bounded, and the two kinds are bounded differently.

`auto` snapshots roll: the eleventh insert into a (user, device) bucket evicts the
oldest *automatic* row and touches no manual one. `manual` snapshots are pinned: the
eleventh create is refused and nothing is deleted — silently dropping the snapshot a
user took before an experiment would destroy exactly what the feature promises.

Mirror image of tests/test_push_subscription_limits.py, at the CRUD layer. The HTTP
surface, and the time-based rules (coalescing, minimum interval), are in
test_config_backup_retention.py.
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.crud import config_backup as crud_backup
from app.database import Base
from app.models import db as models_db
# Vehicle relates to ChargeLog by name; without the module imported the mapper cannot
# resolve it and every query in this file fails at configure time.
from app.services.charge_logger import models as charge_models  # noqa: F401


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    owner = models_db.User(username="owner", email="owner@example.com",
                           hashed_password="x", is_active=True)
    session.add(owner)
    session.commit()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _fifo(monkeypatch):
    """Time plays no part here: a pure FIFO window, no minimum interval."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_AUTO_COALESCE_MINUTES", 0)
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)


def _owner(db) -> models_db.User:
    return db.query(models_db.User).filter_by(username="owner").one()


def _doc(n) -> str:
    return json.dumps({"schemaVersion": 1, "settings": {"n": n}})


def _store(db, owner, n, *, kind="auto", device="abcd1234", label=None):
    return crud_backup.store_backup(
        db, owner.id, kind=kind, payload=_doc(n), device_id=device, device_name="Phone",
        label=label, app_version="2.3.0", platform="android", schema_version=1,
    )


def _rows(db, kind=None):
    query = db.query(models_db.ConfigBackup)
    if kind:
        query = query.filter_by(kind=kind)
    return query.order_by(models_db.ConfigBackup.id).all()


def test_the_eleventh_auto_upload_evicts_the_oldest_auto_and_no_manual(db):
    owner = _owner(db)
    _store(db, owner, "keep", kind="manual", label="before experiment")

    for n in range(settings.CONFIG_BACKUP_MAX_AUTO + 1):
        _, outcome = _store(db, owner, n)
        assert outcome is crud_backup.StoreOutcome.CREATED

    autos = _rows(db, "auto")
    assert len(autos) == settings.CONFIG_BACKUP_MAX_AUTO
    surviving = {json.loads(row.payload)["settings"]["n"] for row in autos}
    assert 0 not in surviving, "the oldest auto snapshot outlived a newer one"
    assert settings.CONFIG_BACKUP_MAX_AUTO in surviving

    manuals = _rows(db, "manual")
    assert [row.label for row in manuals] == ["before experiment"]


def test_the_eleventh_manual_create_is_refused_and_deletes_nothing(db):
    owner = _owner(db)
    for n in range(settings.CONFIG_BACKUP_MAX_MANUAL):
        _store(db, owner, n, kind="manual")

    with pytest.raises(crud_backup.ManualLimitReached):
        _store(db, owner, "one too many", kind="manual")

    assert len(_rows(db, "manual")) == settings.CONFIG_BACKUP_MAX_MANUAL


def test_a_byte_identical_reupload_consumes_no_window_slot(db):
    owner = _owner(db)
    first, created = _store(db, owner, "same")
    again, outcome = _store(db, owner, "same")

    assert created is crud_backup.StoreOutcome.CREATED
    assert outcome is crud_backup.StoreOutcome.DEDUPLICATED
    assert again.id == first.id
    assert len(_rows(db)) == 1


def test_a_deduplicated_upload_takes_the_new_label(db):
    """A manual "create now" with unchanged content is answered with the row it
    already has — but the label the user just typed is not thrown away."""
    owner = _owner(db)
    first, _ = _store(db, owner, "same", kind="manual", label="first")
    again, outcome = _store(db, owner, "same", kind="manual", label="before experiment")

    assert outcome is crud_backup.StoreOutcome.DEDUPLICATED
    assert again.id == first.id
    assert again.label == "before experiment"
    assert len(_rows(db, "manual")) == 1


def test_the_content_digest_ignores_meta_and_key_order():
    base = {"schemaVersion": 1, "settings": {"a": 1, "b": 2}, "vehicles": [{"id": "X"}]}
    stamped = {**base, "meta": {"createdAt": "2026-09-01T20:00:00Z", "kind": "auto"}}
    restamped = {**base, "meta": {"createdAt": "2026-09-02T20:00:00Z", "kind": "manual"}}
    reordered = {"vehicles": [{"id": "X"}], "settings": {"b": 2, "a": 1}, "schemaVersion": 1}
    changed = {**base, "settings": {"a": 1, "b": 3}}

    assert crud_backup.content_digest(stamped) == crud_backup.content_digest(restamped)
    assert crud_backup.content_digest(stamped) == crud_backup.content_digest(reordered)
    assert crud_backup.content_digest(stamped) != crud_backup.content_digest(changed)


def test_store_backup_computes_the_digest_when_none_is_passed(db):
    owner = _owner(db)
    row, _ = _store(db, owner, "x")
    assert row.payload_sha256 == crud_backup.content_digest(json.loads(_doc("x")))


def test_a_listing_carries_the_summary_fields_and_never_the_payload(db):
    owner = _owner(db)
    _store(db, owner, "x", kind="manual", label="lbl")

    (row,) = crud_backup.list_backups(db, owner.id)

    assert row.schema_version == 1
    assert row.device_id == "abcd1234"
    assert row.device_name == "Phone"
    assert row.label == "lbl"
    assert "payload" not in row._fields, "the listing loaded the document"


def test_deleting_a_user_removes_their_backups(db):
    """ORM cascade — SQLite does not enforce the ON DELETE, see app/database.py."""
    owner = _owner(db)
    _store(db, owner, 1)
    _store(db, owner, 2, kind="manual")

    db.delete(owner)
    db.commit()

    assert db.query(models_db.ConfigBackup).count() == 0
