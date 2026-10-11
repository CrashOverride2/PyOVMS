"""
Support mode in the web UI (app/routers/ui/vehicles.py, _vehicle_support.html).

What is pinned here:

* the owner switches it, with CSRF, for an offered duration only; an admin cannot;
* an admin without a grant is turned away from the vehicle and charge pages, the
  logs and the terminal — and let in while one runs, each access a SUPPORT_ACCESS
  event, throttled per kind, a command every time and only by its first words;
* trips and every notification target stay the owner's, grant or not;
* a grant past its time locks the admin out at once, without any sweep;
* the admins are mailed when it is switched on, not when it is extended;
* the admin dashboard marks the vehicles an admin may open now.
"""

import datetime
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app import notifications, security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager
from app.services import support_mode

PASSWORD = "CorrectHorse1!Battery"
VID = "SUPCAR"


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
    db.query(models_db.PushSubscription).delete()
    db.query(models_db.Vehicle).delete()
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
    support_mode.reset_throttles()
    yield
    support_mode.reset_throttles()


@pytest.fixture
def client():
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


@pytest.fixture
def mails(monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "send_support_mode_enabled_admin_notification",
                        lambda **kw: sent.append(kw))
    return sent


def _make_user(db, username, *, admin=False):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=admin, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_vehicle(db, owner, *, until=None):
    vehicle = models_db.Vehicle(
        vehicle_id=VID, owner_id=owner.id, protocol="v3", enable_charge_logging=True,
        encrypted_server_password=b"x",
        support_until=until, support_granted_by_id=owner.id if until else None,
    )
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _setup(db, *, granted):
    alice = _make_user(db, "alice")
    root = _make_user(db, "root", admin=True)
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2) if granted else None
    vehicle = _make_vehicle(db, alice, until=until)
    return alice, root, vehicle


def _login(client, username):
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    assert token is not None
    response = client.post(
        "/login",
        data={"username": username, "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _csrf(client):
    return client.get("/csrf-token/refresh").json()["csrf_token"]


def _access_events(db, kind=None):
    db.expire_all()
    rows = db.query(models_db.SecurityEvent).filter_by(event_type="support_access").all()
    return [r for r in rows if kind is None or r.details.get("kind") == kind]


# --- the owner's switch -----------------------------------------------------------

def test_owner_sees_the_support_tab(client, db):
    _setup(db, granted=False)
    _login(client, "alice")
    html = client.get(f"/vehicle/{VID}").text
    assert 'data-tab="support"' in html
    assert "ui_enable_support_mode" not in html  # rendered as a URL, not a name
    assert f"/vehicle/{VID}/support/enable" in html


def test_owner_enables_and_ends_support_mode(client, db, mails):
    _, _, vehicle = _setup(db, granted=False)
    _login(client, "alice")

    response = client.post(f"/vehicle/{VID}/support/enable",
                           data={"duration": "24h", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    assert "tab=support" in response.headers["location"]
    assert "success_message" in response.headers["location"]
    db.refresh(vehicle)
    assert vehicle.support_until is not None
    assert vehicle.support_granted_by_id == vehicle.owner_id
    assert len(mails) == 1 and mails[0]["vehicle_id"] == VID and mails[0]["owner_username"] == "alice"
    assert db.query(models_db.SecurityEvent).filter_by(event_type="support_mode_enabled").count() == 1

    response = client.post(f"/vehicle/{VID}/support/disable",
                           data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    assert "success_message" in response.headers["location"]
    db.refresh(vehicle)
    assert vehicle.support_until is None
    assert db.query(models_db.SecurityEvent).filter_by(event_type="support_mode_disabled").count() == 1


def test_extending_a_running_grant_mails_nobody(client, db, mails):
    _, _, vehicle = _setup(db, granted=True)
    _login(client, "alice")
    response = client.post(f"/vehicle/{VID}/support/enable",
                           data={"duration": "7d", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    assert mails == []
    db.refresh(vehicle)
    remaining = vehicle.support_until.replace(tzinfo=datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)
    assert remaining > datetime.timedelta(days=6)


def test_switching_off_and_on_again_mails_once(client, db, mails):
    _setup(db, granted=False)
    _login(client, "alice")
    for _ in range(2):
        client.post(f"/vehicle/{VID}/support/enable",
                    data={"duration": "24h", "csrf_token": _csrf(client)}, follow_redirects=False)
        client.post(f"/vehicle/{VID}/support/disable",
                    data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert len(mails) == 1


def test_an_unoffered_duration_is_refused(client, db, mails):
    _, _, vehicle = _setup(db, granted=False)
    _login(client, "alice")
    response = client.post(f"/vehicle/{VID}/support/enable",
                           data={"duration": "999d", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert "error_message" in response.headers["location"]
    db.refresh(vehicle)
    assert vehicle.support_until is None
    assert mails == []


def test_enabling_needs_a_valid_csrf_token(client, db, mails):
    _, _, vehicle = _setup(db, granted=False)
    _login(client, "alice")
    response = client.post(f"/vehicle/{VID}/support/enable",
                           data={"duration": "24h", "csrf_token": "garbage"}, follow_redirects=False)
    # The router-wide csrf_protect dependency answers before the route does.
    assert response.status_code == 403
    db.refresh(vehicle)
    assert vehicle.support_until is None


def test_an_admin_cannot_switch_it(client, db, mails):
    _, _, vehicle = _setup(db, granted=False)
    _login(client, "root")
    response = client.post(f"/vehicle/{VID}/support/enable",
                           data={"duration": "30d", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert "error_message" in response.headers["location"]
    db.refresh(vehicle)
    assert vehicle.support_until is None


def test_an_admin_cannot_end_someone_elses_grant(client, db):
    _, _, vehicle = _setup(db, granted=True)
    _login(client, "root")
    client.post(f"/vehicle/{VID}/support/disable", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    db.refresh(vehicle)
    assert vehicle.support_until is not None


def test_the_flash_message_is_translated(client, db, mails):
    _setup(db, granted=False)
    _login(client, "alice")
    response = client.post(f"/vehicle/{VID}/support/enable",
                           data={"duration": "24h", "csrf_token": _csrf(client)},
                           headers={"Accept-Language": "de"}, follow_redirects=False)
    assert "Support-Modus+aktiviert" in response.headers["location"]


# --- the admin's side -------------------------------------------------------------

def test_admin_without_grant_is_turned_away(client, db):
    _, _, vehicle = _setup(db, granted=False)
    _login(client, "root")
    response = client.get(f"/vehicle/{VID}", follow_redirects=False)
    assert response.status_code == 303
    assert "/admin" in response.headers["location"]
    response = client.get(f"/vehicle/{VID}/charge/{uuid.uuid4()}", follow_redirects=False)
    assert response.status_code == 303
    assert client.get(f"/vehicle/{VID}/datalogs").status_code == 403
    assert client.get(f"/vehicle/{vehicle.id}/crashlogs/download").status_code == 403
    response = client.post(f"/vehicle/{VID}/command-ajax",
                           data={"command_str": "stat", "csrf_token": _csrf(client)})
    assert response.status_code == 403
    assert _access_events(db) == []


def test_admin_under_a_grant_opens_the_vehicle(client, db):
    _setup(db, granted=True)
    _login(client, "root")
    response = client.get(f"/vehicle/{VID}")
    assert response.status_code == 200
    html = response.text
    assert 'data-tab="support"' in html
    assert 'data-tab="charges"' in html
    # Trips and notifications are the owner's, grant or not.
    assert 'data-tab="notifications"' not in html
    assert 'data-tab="trips"' not in html
    assert "push/add-ntfy" not in html
    events = _access_events(db, "page")
    assert len(events) == 1
    assert events[0].username == "root"
    assert events[0].details["owner_username"] == "alice"


def test_page_views_are_throttled(client, db):
    _setup(db, granted=True)
    _login(client, "root")
    for _ in range(3):
        assert client.get(f"/vehicle/{VID}").status_code == 200
    assert len(_access_events(db, "page")) == 1


def test_every_command_is_recorded_by_its_first_words(client, db, monkeypatch):
    from app.models import api as models_api
    from app.routers.ui import vehicles as ui_vehicles

    async def fake_send(vehicle, command, preference):
        return models_api.CommandResponse(vehicle_id=vehicle.vehicle_id, response_data="ok", success=True)

    monkeypatch.setattr(ui_vehicles, "send_command_to_vehicle", fake_send)
    _setup(db, granted=True)
    _login(client, "root")
    for _ in range(2):
        response = client.post(f"/vehicle/{VID}/command-ajax",
                               data={"command_str": "config set vehicle password s3cr3t", "csrf_token": _csrf(client)})
        assert response.status_code == 200, response.text
    events = _access_events(db, "command")
    assert len(events) == 2
    assert events[0].details["command"] == "config set"
    assert "s3cr3t" not in str(events[0].details)


def test_admin_may_not_touch_the_notification_targets(client, db):
    _, _, vehicle = _setup(db, granted=True)
    db.add(models_db.PushSubscription(vehicle_id_fk=vehicle.id, device_id="d1", push_type="email",
                                      endpoint="alice@example.com"))
    db.commit()
    sub_id = db.query(models_db.PushSubscription).one().id
    _login(client, "root")
    client.post(f"/vehicle/{VID}/push/add-email",
                data={"notification_email": "root@example.com", "csrf_token": _csrf(client)})
    client.post(f"/vehicle/{VID}/push/{sub_id}/delete", data={"csrf_token": _csrf(client)})
    db.expire_all()
    assert [s.endpoint for s in db.query(models_db.PushSubscription).all()] == ["alice@example.com"]


def test_admin_may_not_open_a_trip_even_under_a_grant(client, db):
    _setup(db, granted=True)
    _login(client, "root")
    response = client.get(f"/vehicle/{VID}/trip/{uuid.uuid4()}", follow_redirects=False)
    assert response.status_code == 303
    assert "/admin" in response.headers["location"]


def test_an_expired_grant_locks_the_admin_out_at_once(client, db):
    _, _, vehicle = _setup(db, granted=True)
    vehicle.support_until = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    db.commit()
    _login(client, "root")
    assert client.get(f"/vehicle/{VID}", follow_redirects=False).status_code == 303


def test_admin_still_administers_without_a_grant(client, db):
    _, _, vehicle = _setup(db, granted=False)
    _login(client, "root")
    assert client.get(f"/vehicle/{vehicle.id}/edit", follow_redirects=False).status_code == 200


def test_admin_dashboard_marks_the_granted_vehicle(client, db):
    _setup(db, granted=True)
    _login(client, "root")
    html = client.get("/admin/dashboard").text
    assert f'/vehicle/{VID}"' in html


def test_admin_dashboard_has_no_link_without_a_grant(client, db):
    _setup(db, granted=False)
    _login(client, "root")
    html = client.get("/admin/dashboard").text
    assert f'/vehicle/{VID}"' not in html
