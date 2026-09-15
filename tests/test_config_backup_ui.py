"""
The profile page's backups tab: present only while there is something to show,
download hands out the stored document unchanged, and the label — user text — can
not reach the Content-Disposition header unfiltered.

Driven through the real login form so the session is what a browser would hold.
"""

import json
import re

import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import settings
from app.crud import config_backup as crud_backup
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"


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
    db.query(models_db.SecurityEvent).delete()
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
    """https, because FORCE_SECURE_COOKIES marks the session cookie Secure — over http
    the client stores it and never sends it back, and the login silently does nothing."""
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _make_user(db, username="alice"):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _login(client, username="alice"):
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    assert token is not None, "no csrf_token on the login page"
    response = client.post(
        "/login",
        data={"username": username, "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _session_csrf(client) -> str:
    return client.get("/csrf-token/refresh").json()["csrf_token"]


def _store(db, user, label=None, n=1):
    payload = json.dumps({"schemaVersion": 1, "settings": {"n": n}}, indent=1) + "\n"
    row, _ = crud_backup.store_backup(
        db, user.id, kind="manual", payload=payload, device_id="abcd", device_name="Phone",
        label=label, app_version="2.3.0", platform="ios", schema_version=1,
    )
    return row, payload


def test_the_tab_only_exists_while_there_is_a_backup(client, db):
    user = _make_user(db)
    _login(client)

    assert 'data-tab-btn="backups"' not in client.get("/profile").text

    _store(db, user, label="mine")
    page = client.get("/profile").text
    assert 'data-tab-btn="backups"' in page
    assert 'data-tab-panel="backups"' in page
    assert "mine" in page


def _store_for(db, user, *, kind, label, device, n):
    row, _ = crud_backup.store_backup(
        db, user.id, kind=kind, payload=json.dumps({"schemaVersion": 1, "settings": {"n": n}}),
        device_id=device, device_name=f"Phone {device}", label=label,
        app_version="2.3.0", platform="ios", schema_version=1,
    )
    return row


def test_the_tab_groups_rows_per_device_with_pinned_ones_first(client, db):
    """One block per device, the device with the newest snapshot first; inside a
    block the pinned rows come before the automatic ones even when older."""
    user = _make_user(db)
    _login(client)
    _store_for(db, user, kind="manual", label="a-pinned", device="aaaa", n=1)
    _store_for(db, user, kind="auto", label="a-rolling", device="aaaa", n=2)
    _store_for(db, user, kind="manual", label="b-pinned", device="bbbb", n=3)

    page = client.get("/profile").text
    assert page.count("Phone aaaa") == 1 and page.count("Phone bbbb") == 1, "the device is a header, not a column"
    assert page.index("Phone bbbb") < page.index("Phone aaaa"), "the device with the newest row leads"
    assert page.index("Phone aaaa") < page.index("a-pinned") < page.index("a-rolling"), \
        "pinned before automatic inside a device, whatever the dates say"
    assert "1 manual · 1 automatic" in page and "1 manual · 0 automatic" in page


def test_two_devices_with_one_name_get_a_short_suffix(client, db):
    user = _make_user(db)
    _login(client)
    for device in ("abcd1234abcd1234", "ef01ef01ef01ef01"):
        crud_backup.store_backup(
            db, user.id, kind="manual", payload=json.dumps({"schemaVersion": 1, "settings": {"d": device}}),
            device_id=device, device_name="samsung SM-S911B", label=None,
            app_version=None, platform="android", schema_version=1,
        )
    page = client.get("/profile").text
    assert "abcd" in page and "ef01" in page
    assert "abcd1234abcd1234" not in page, "never the whole hash"


def test_a_renamed_device_renames_its_earlier_rows(db):
    """The app sends the name with every upload; the rows already stored kept
    theirs, so one phone appeared as two devices after a rename."""
    user = _make_user(db)
    same = '{"schemaVersion": 1, "settings": {"n": 1}}'
    other, _ = crud_backup.store_backup(
        db, user.id, kind="manual", payload=same, device_id="ffff", device_name="Tablet",
        label=None, app_version=None, platform=None, schema_version=1)
    crud_backup.store_backup(
        db, user.id, kind="manual", payload=same, device_id="abcd", device_name="samsung SM-S911B",
        label=None, app_version=None, platform=None, schema_version=1)
    _, outcome = crud_backup.store_backup(
        db, user.id, kind="manual", payload=same, device_id="abcd", device_name="Carstens Galaxy",
        label=None, app_version=None, platform=None, schema_version=1)
    assert outcome is crud_backup.StoreOutcome.DEDUPLICATED, "unchanged content still carries the rename"

    db.expire_all()
    names = {r.device_id: r.device_name for r in db.query(models_db.ConfigBackup).all()}
    assert names == {"abcd": "Carstens Galaxy", "ffff": "Tablet"}


def test_download_hands_out_the_stored_document_unchanged(client, db):
    user = _make_user(db)
    row, payload = _store(db, user, label="before experiment")
    _login(client)

    response = client.get(f"/profile/config-backups/{row.id}/download")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert disposition.endswith('.json"')
    assert response.content == payload.encode("utf-8")


def test_a_hostile_label_cannot_reach_the_header(client, db):
    user = _make_user(db)
    row, _ = _store(db, user, label='evil"; x=y\r\nX-Injected: 1')
    _login(client)

    response = client.get(f"/profile/config-backups/{row.id}/download")

    assert response.status_code == 200
    assert "x-injected" not in {k.lower() for k in response.headers}
    filename = re.search(r'filename="([^"]*)"', response.headers["content-disposition"]).group(1)
    assert re.fullmatch(r"[A-Za-z0-9_.-]+", filename), filename


def test_someone_elses_backup_is_not_found(client, db):
    alice = _make_user(db, "alice")
    _make_user(db, "bob")
    row, _ = _store(db, alice)
    _login(client, "bob")

    assert client.get(f"/profile/config-backups/{row.id}/download").status_code == 404


def test_delete_needs_a_valid_csrf_token(client, db):
    user = _make_user(db)
    row, _ = _store(db, user)
    _login(client)

    response = client.post(
        f"/profile/config-backups/{row.id}/delete",
        data={"csrf_token": "garbage"}, follow_redirects=False,
    )

    assert response.status_code == 403
    assert db.query(models_db.ConfigBackup).count() == 1


def test_delete_removes_the_row_and_returns_to_the_tab(client, db):
    user = _make_user(db)
    row, _ = _store(db, user)
    _login(client)

    response = client.post(
        f"/profile/config-backups/{row.id}/delete",
        data={"csrf_token": _session_csrf(client)}, follow_redirects=False,
    )

    assert response.status_code == 303
    assert "tab=backups" in response.headers["location"]
    assert "success_message" in response.headers["location"]
    assert db.query(models_db.ConfigBackup).count() == 0


def test_deleting_someone_elses_backup_deletes_nothing(client, db):
    alice = _make_user(db, "alice")
    _make_user(db, "bob")
    row, _ = _store(db, alice)
    _login(client, "bob")

    response = client.post(
        f"/profile/config-backups/{row.id}/delete",
        data={"csrf_token": _session_csrf(client)}, follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error_message" in response.headers["location"]
    assert db.query(models_db.ConfigBackup).count() == 1


def test_the_kill_switch_leaves_the_profile_tab_alone(client, db, monkeypatch):
    """CONFIG_BACKUP_ENABLED=false stops the app from taking snapshots and being
    handed them; what is stored stays the user's to see, download and delete.
    An operator switching the feature off must not strand anyone's data."""
    user = _make_user(db)
    row, payload = _store(db, user, label="mine")
    _login(client)
    monkeypatch.setattr(settings, "CONFIG_BACKUP_ENABLED", False)

    assert 'data-tab-btn="backups"' in client.get("/profile").text
    download = client.get(f"/profile/config-backups/{row.id}/download")
    assert download.status_code == 200
    assert download.content == payload.encode("utf-8")

    response = client.post(
        f"/profile/config-backups/{row.id}/delete",
        data={"csrf_token": _session_csrf(client)}, follow_redirects=False,
    )
    assert response.status_code == 303
    assert db.query(models_db.ConfigBackup).count() == 0
