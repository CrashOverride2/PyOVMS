"""
The retention rules of configuration backups, over HTTP.

Three of them decide what the rolling window actually holds, and none of them is
visible in the schema:

  * **Per device.** Two phones never deduplicate against each other, so a shared
    window would be filled in alternation and the phone in the drawer — the one
    whose snapshot you want when the other breaks — would end up with none.
  * **Coalescing.** An auto snapshot younger than the coalesce window replaces the
    newest one instead of adding a row. Without it, an evening of theme editing
    with eight app switches evicts every older state. The window is measured from
    the newest row's created_at, which is the date of its *content*: a
    deduplicated upload leaves it alone, or a month of daily confirmations made
    the stable state "an hour old" and the first real change replaced it.
  * **Minimum interval.** A client whose dirty flag never clears is answered 200
    without a write — for *unchanged* content only. Changed content is stored,
    however soon it arrives: the app clears its dirty flag on 200.
  * **So many devices, no more.** The device id is the client's to choose, so
    the number of auto windows per user is capped; a new device beyond the cap
    evicts the auto rows of the device not heard from the longest.

Plus the one transition a snapshot may make: auto -> manual, which pins it.
"""

import datetime
import json

import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
URL = "/api/v1/config-backups"


@pytest.fixture(scope="module", autouse=True)
def _schema():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _clean(db):
    db.query(models_db.ConfigBackup).delete()
    db.query(models_db.ApiKey).delete()
    db.query(models_db.User).delete()
    db.query(models_db.BlockedIP).delete()
    db.query(models_db.SecurityFailure).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    security_manager._blocked_usernames.clear()
    security_manager._username_failures.clear()
    yield


@pytest.fixture
def client():
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def fifo(monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_BACKUP_AUTO_COALESCE_MINUTES", 0)
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)


def _user_with_key(db, username="alice"):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _, plain_key = crud.apikey.create_api_key(db, user.id, f"{username}-key")
    return user, plain_key


def _doc(n) -> str:
    return json.dumps({"schemaVersion": 1, "settings": {"n": n}})


def _upload(client, key, n, *, kind="auto", device="aaaa", **extra):
    body = {"kind": kind, "payload": _doc(n), **extra}
    if device is not None:
        body["device_id"] = device
    return client.post(URL, json=body, headers={"X-API-Key": key})


def _rows(db, user, kind=None, device=None):
    query = db.query(models_db.ConfigBackup).filter_by(owner_id=user.id)
    if kind:
        query = query.filter_by(kind=kind)
    if device is not None:
        query = query.filter_by(device_id=device)
    return query.order_by(models_db.ConfigBackup.id).all()


def _n(row) -> object:
    return json.loads(row.payload)["settings"]["n"]


# --- per device -------------------------------------------------------------------

def test_two_devices_keep_two_windows(client, db, fifo):
    user, key = _user_with_key(db)
    for n in range(settings.CONFIG_BACKUP_MAX_AUTO):
        assert _upload(client, key, f"a{n}", device="aaaa").status_code == 201
        assert _upload(client, key, f"b{n}", device="bbbb").status_code == 201

    assert len(_rows(db, user)) == 2 * settings.CONFIG_BACKUP_MAX_AUTO

    assert _upload(client, key, "a-extra", device="aaaa").status_code == 201

    a = _rows(db, user, device="aaaa")
    b = _rows(db, user, device="bbbb")
    assert len(a) == settings.CONFIG_BACKUP_MAX_AUTO and "a0" not in {_n(r) for r in a}
    assert len(b) == settings.CONFIG_BACKUP_MAX_AUTO and "b0" in {_n(r) for r in b}, \
        "device A's upload evicted a snapshot of device B"


def test_uploads_without_a_device_id_share_one_bucket(client, db, fifo):
    user, key = _user_with_key(db)
    for n in range(settings.CONFIG_BACKUP_MAX_AUTO + 3):
        assert _upload(client, key, n, device=None).status_code == 201

    rows = _rows(db, user)
    assert len(rows) == settings.CONFIG_BACKUP_MAX_AUTO
    assert all(row.device_id is None for row in rows)


# --- coalescing -------------------------------------------------------------------

def test_a_second_auto_snapshot_inside_the_window_replaces_the_first(client, db, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)
    user, key = _user_with_key(db)

    assert _upload(client, key, 1).status_code == 201
    second = _upload(client, key, 2)
    assert second.status_code == 200, "a coalesced upload is not a new row"

    (row,) = _rows(db, user)
    assert _n(row) == 2, "the row holds the older content"
    assert second.json()["id"] == row.id


def test_an_auto_snapshot_after_the_window_is_a_new_row(client, db, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)
    user, key = _user_with_key(db)
    assert _upload(client, key, 1).status_code == 201

    (row,) = _rows(db, user)
    row.created_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        minutes=settings.CONFIG_BACKUP_AUTO_COALESCE_MINUTES + 1)
    db.commit()

    assert _upload(client, key, 2).status_code == 201
    assert [_n(r) for r in _rows(db, user)] == [1, 2]


def test_coalesce_window_zero_means_fifo(client, db, fifo):
    user, key = _user_with_key(db)
    assert _upload(client, key, 1).status_code == 201
    assert _upload(client, key, 2).status_code == 201
    assert len(_rows(db, user)) == 2


def test_manual_snapshots_never_coalesce(client, db, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)
    user, key = _user_with_key(db)
    assert _upload(client, key, 1, kind="manual").status_code == 201
    assert _upload(client, key, 2, kind="manual").status_code == 201
    assert len(_rows(db, user, kind="manual")) == 2


def _app_doc(n, created_at: str) -> str:
    """The shape the app sends: a fresh meta.createdAt on every snapshot."""
    return json.dumps({
        "schemaVersion": 1,
        "meta": {"createdAt": created_at, "appVersion": "2.3.0", "platform": "android",
                 "deviceName": "Pixel", "deviceId": "aaaa", "kind": "auto", "label": None},
        "settings": {"n": n}, "vehicles": [{"id": "CAR1"}], "activeVehicleId": "CAR1",
        "commands": {"custom": [], "predefinedCustomizations": []},
    })


def _age_newest(db, user, minutes: int) -> None:
    row = _rows(db, user)[-1]
    row.created_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)
    db.commit()


def test_an_unchanged_configuration_deduplicates_whatever_meta_says(client, db, monkeypatch):
    """The app stamps every snapshot with a new meta.createdAt. Hashed as text, two
    uploads of the same configuration never matched, and past the coalesce window each
    was a new row: a phone opened once a day filled the window with ten identical
    snapshots and evicted every real one."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)
    user, key = _user_with_key(db)
    past_the_window = settings.CONFIG_BACKUP_AUTO_COALESCE_MINUTES + 1

    def post(payload):
        return client.post(URL, json={"kind": "auto", "device_id": "aaaa", "payload": payload},
                           headers={"X-API-Key": key})

    assert post(_app_doc(1, "2026-09-01T20:00:00Z")).status_code == 201
    _age_newest(db, user, past_the_window)

    same = post(_app_doc(1, "2026-09-02T20:00:00Z"))
    assert same.status_code == 200, "same configuration, new createdAt: must deduplicate"
    assert len(_rows(db, user)) == 1

    _age_newest(db, user, past_the_window)
    assert post(_app_doc(2, "2026-09-03T20:00:00Z")).status_code == 201, "a real change is a row"
    assert [_n(r) for r in _rows(db, user)] == [1, 2]


# --- minimum interval -------------------------------------------------------------

def test_an_unchanged_upload_within_the_minimum_interval_writes_nothing(client, db):
    user, key = _user_with_key(db)
    assert _upload(client, key, 1, label="first").status_code == 201
    throttled = _upload(client, key, 1, label="second")

    assert throttled.status_code == 200
    (row,) = _rows(db, user)
    assert throttled.json()["id"] == row.id
    assert row.label == "first", "not even the label: the throttled path is a pure read"


def test_a_renamed_device_within_the_minimum_interval_is_renamed(client, db):
    """The app forgets its digest on a rename so that exactly one upload of
    unchanged content follows. The throttled path writes nothing, so it must not
    be the one that answers it."""
    user, key = _user_with_key(db)
    assert _upload(client, key, 1, device_name="Pixel").status_code == 201
    renamed = _upload(client, key, 1, device_name="Carstens Pixel")

    assert renamed.status_code == 200
    (row,) = _rows(db, user)
    assert row.device_name == "Carstens Pixel"
    assert renamed.json()["device_name"] == "Carstens Pixel"


def test_a_coalesced_upload_without_a_name_keeps_the_stored_one(client, db, monkeypatch):
    """The name belongs to the device, not to the content it replaces."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)
    user, key = _user_with_key(db)
    assert _upload(client, key, 1, device_name="Pixel").status_code == 201
    coalesced = _upload(client, key, 2)

    assert coalesced.status_code == 200
    (row,) = _rows(db, user)
    assert _n(row) == 2
    assert row.device_name == "Pixel"
    assert coalesced.json()["device_name"] == "Pixel"


def test_a_changed_upload_within_the_minimum_interval_is_stored(client, db):
    """The interval used to throttle changed content too, answered 200 — and the
    app, which treats 200 as "saved", cleared its dirty flag over a change that
    no snapshot held. Now it coalesces, like any change inside the window."""
    user, key = _user_with_key(db)
    assert _upload(client, key, 1).status_code == 201
    changed = _upload(client, key, 2)

    assert changed.status_code == 200, "inside the coalesce window: replaced, not added"
    (row,) = _rows(db, user)
    assert _n(row) == 2, "the change the app believes is saved must be"
    assert changed.json()["id"] == row.id


# --- created_at is the date of the content ------------------------------------------

def test_a_configuration_stable_for_a_month_survives_its_first_change(client, db, monkeypatch):
    """Dedup used to refresh created_at, and the coalesce window is measured from
    it: a phone opened daily kept its unchanged snapshot "an hour old", so the
    first real change after a month replaced the stable state instead of adding
    a row — the very snapshot wanted back after a mistake, gone."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MIN_AUTO_INTERVAL_SECONDS", 0)
    user, key = _user_with_key(db)
    assert _upload(client, key, "stable").status_code == 201
    _age_newest(db, user, 30 * 24 * 60)
    stable_since = _rows(db, user)[0].created_at

    assert _upload(client, key, "stable").status_code == 200, "confirmed daily, unchanged"
    db.expire_all()
    assert _rows(db, user)[0].created_at == stable_since, "a confirmation is not a change"

    assert _upload(client, key, "changed").status_code == 201, "a month later: a new row, not a replacement"
    assert [_n(r) for r in _rows(db, user)] == ["stable", "changed"]


# --- so many devices, no more ---------------------------------------------------------

def _devices_with_auto_rows(db, user):
    return sorted({r.device_id for r in _rows(db, user, kind="auto")}, key=str)


def test_a_new_device_beyond_the_cap_evicts_the_stalest_devices_auto_rows(client, db, fifo, monkeypatch):
    """The device id is the client's to choose; without the cap every new one
    opened another window and the only bound on the row count was the quota."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_DEVICES", 3)
    user, key = _user_with_key(db)
    for i, device in enumerate(("aaaa", "bbbb", "cccc")):
        assert _upload(client, key, i, device=device).status_code == 201
        _age_newest(db, user, minutes=(3 - i) * 60)  # aaaa is the stalest
    assert _devices_with_auto_rows(db, user) == ["aaaa", "bbbb", "cccc"]

    assert _upload(client, key, 9, device="dddd").status_code == 201
    assert _devices_with_auto_rows(db, user) == ["bbbb", "cccc", "dddd"], \
        "the device not heard from the longest made room"
    assert len(_rows(db, user)) == 3


def test_known_devices_never_evict_one_another(client, db, fifo, monkeypatch):
    """At the cap, a fleet of real phones re-uploading costs nothing; only an
    unknown id does."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_DEVICES", 2)
    user, key = _user_with_key(db)
    assert _upload(client, key, 1, device="aaaa").status_code == 201
    assert _upload(client, key, 2, device="bbbb").status_code == 201
    for n in range(3, 8):
        assert _upload(client, key, n, device="aaaa").status_code == 201
        assert _upload(client, key, n, device="bbbb").status_code == 201
    assert _devices_with_auto_rows(db, user) == ["aaaa", "bbbb"]


def test_pinned_rows_of_an_evicted_device_survive(client, db, fifo, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_DEVICES", 1)
    user, key = _user_with_key(db)
    assert _upload(client, key, "keep", kind="manual", device="aaaa").status_code == 201
    assert _upload(client, key, "roll", device="aaaa").status_code == 201
    assert _upload(client, key, "new", device="bbbb").status_code == 201

    assert _devices_with_auto_rows(db, user) == ["bbbb"]
    (pinned,) = _rows(db, user, kind="manual")
    assert pinned.device_id == "aaaa" and _n(pinned) == "keep"


def test_devices_with_only_pinned_rows_do_not_count_against_the_cap(client, db, fifo, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_DEVICES", 1)
    user, key = _user_with_key(db)
    assert _upload(client, key, "pin", kind="manual", device="aaaa").status_code == 201
    assert _upload(client, key, "auto", device="bbbb").status_code == 201
    assert _upload(client, key, "auto", device="bbbb").status_code == 200, "same device, same content"
    assert _devices_with_auto_rows(db, user) == ["bbbb"]
    assert len(_rows(db, user)) == 2


def test_the_row_count_per_user_is_bounded(client, db, fifo, monkeypatch):
    """The property the cap exists for: MAX_DEVICES * MAX_AUTO + MAX_MANUAL rows,
    whatever a client does with device ids."""
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_DEVICES", 3)
    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_AUTO", 2)
    user, key = _user_with_key(db)
    for i in range(40):
        assert _upload(client, key, i, device=f"{i:04x}").status_code == 201
        assert _upload(client, key, i + 100, device=f"{i:04x}").status_code == 201
    assert len(_rows(db, user)) == 3 * 2


# --- pinning ----------------------------------------------------------------------

def test_pinning_takes_a_snapshot_out_of_the_rolling_window(client, db, fifo):
    user, key = _user_with_key(db)
    pinned_id = _upload(client, key, "pin me").json()["id"]

    response = client.patch(f"{URL}/{pinned_id}", json={"kind": "manual"}, headers={"X-API-Key": key})
    assert response.status_code == 200
    assert response.json()["kind"] == "manual"

    for n in range(settings.CONFIG_BACKUP_MAX_AUTO + 2):
        assert _upload(client, key, n).status_code == 201

    assert db.query(models_db.ConfigBackup).get(pinned_id) is not None
    assert len(_rows(db, user, kind="auto")) == settings.CONFIG_BACKUP_MAX_AUTO


def test_a_manual_snapshot_cannot_be_pushed_back_into_the_window(client, db):
    _, key = _user_with_key(db)
    pinned_id = _upload(client, key, 1, kind="manual").json()["id"]

    response = client.patch(f"{URL}/{pinned_id}", json={"kind": "auto"}, headers={"X-API-Key": key})
    assert response.status_code == 422


def test_pinning_respects_the_manual_cap(client, db, fifo):
    _, key = _user_with_key(db)
    for n in range(settings.CONFIG_BACKUP_MAX_MANUAL):
        assert _upload(client, key, n, kind="manual").status_code == 201
    auto_id = _upload(client, key, "auto").json()["id"]

    response = client.patch(f"{URL}/{auto_id}", json={"kind": "manual"}, headers={"X-API-Key": key})
    assert response.status_code == 409


def test_pinning_someone_elses_snapshot_is_not_found(client, db):
    _, alice_key = _user_with_key(db, "alice")
    _, bob_key = _user_with_key(db, "bob")
    alice_id = _upload(client, alice_key, 1).json()["id"]

    response = client.patch(f"{URL}/{alice_id}", json={"kind": "manual"}, headers={"X-API-Key": bob_key})
    assert response.status_code == 404
