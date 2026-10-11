"""
Support mode on the JSON APIs (/api/v1, /api/chargelogs/v1) with an admin's API key.

Admins used to pass every one of these checks unconditionally. Now:

* the vehicle list holds the admin's own vehicles and the granted ones, no others;
* the data routes answer 403 without a grant and 200 with one, audited;
* administration (PUT/DELETE of the record) needs no grant;
* the charge and event API follow the same gate;
* every notification route — registration, manual notify, badge, push targets —
  stays the owner's, grant or not.
"""

import datetime

import pytest
from fastapi.testclient import TestClient

from app import crud
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager
from app.services import support_mode

VID = "APISUP"
OTHER = "APIOTHER"


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


def _user(db, name, admin=False):
    user = models_db.User(username=name, email=f"{name}@example.com", hashed_password="x",
                          is_active=True, is_admin=admin)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _vehicle(db, owner, vid, *, granted=False):
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1) if granted else None
    vehicle = models_db.Vehicle(vehicle_id=vid, owner_id=owner.id, protocol="v3", enable_charge_logging=True,
                                encrypted_server_password=b"x", support_until=until,
                                support_granted_by_id=owner.id if granted else None)
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _setup(db, *, granted):
    alice = _user(db, "alice")
    bob = _user(db, "bob")
    admin = _user(db, "root", admin=True)
    vehicle = _vehicle(db, alice, VID, granted=granted)
    _vehicle(db, bob, OTHER)
    _, key = crud.apikey.create_api_key(db=db, user_id=admin.id, name="admin key")
    return vehicle, {"X-API-Key": key}


DATA_ROUTES = [
    ("get", "/api/v1/vehicles/{db_id}"),
    ("get", f"/api/v1/vehicles/{VID}/metrics/available"),
    ("get", f"/api/v1/vehicle_state/{VID}"),
    ("get", f"/api/v1/vehicles/{VID}/datalogs"),
    ("get", f"/api/v1/vehicles/{VID}/logs"),
    ("get", f"/api/chargelogs/v1/vehicles/{VID}/charges"),
    ("get", f"/api/chargelogs/v1/vehicles/{VID}/stats"),
    ("get", f"/api/chargelogs/v1/vehicles/{VID}/events"),
]


def _call(client, method, path, headers, vehicle):
    return getattr(client, method)(path.format(db_id=vehicle.id), headers=headers)


def test_the_list_holds_only_granted_vehicles(client, db):
    _, headers = _setup(db, granted=True)
    ids = [v["vehicle_id"] for v in client.get("/api/v1/vehicles", headers=headers).json()]
    assert ids == [VID]


def test_without_a_grant_the_list_is_empty(client, db):
    _, headers = _setup(db, granted=False)
    assert client.get("/api/v1/vehicles", headers=headers).json() == []


@pytest.mark.parametrize("method,path", DATA_ROUTES)
def test_data_routes_are_closed_without_a_grant(client, db, method, path):
    vehicle, headers = _setup(db, granted=False)
    assert _call(client, method, path, headers, vehicle).status_code == 403


@pytest.mark.parametrize("method,path", DATA_ROUTES)
def test_data_routes_open_under_a_grant(client, db, method, path):
    vehicle, headers = _setup(db, granted=True)
    response = _call(client, method, path, headers, vehicle)
    assert response.status_code == 200, response.text
    db.expire_all()
    events = db.query(models_db.SecurityEvent).filter_by(event_type="support_access").all()
    assert len(events) == 1
    # No Request reaches these routes; the address comes from SecurityMiddleware.
    assert events[0].ip_address == "testclient"


def test_an_expired_grant_closes_the_api(client, db):
    vehicle, headers = _setup(db, granted=True)
    vehicle.support_until = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    db.commit()
    assert client.get(f"/api/v1/vehicle_state/{VID}", headers=headers).status_code == 403


def test_administration_needs_no_grant(client, db):
    vehicle, headers = _setup(db, granted=False)
    response = client.put(f"/api/v1/vehicles/{vehicle.id}", json={"vehicle_name": "Renamed"}, headers=headers)
    assert response.status_code == 200, response.text


OWNER_ONLY = [
    ("post", f"/api/v1/notify/{VID}", {"message": "hi"}),
    ("post", f"/api/v1/vehicles/{VID}/reset-badge", None),
    ("post", f"/api/v1/vehicles/{VID}/push/fcm", {"token": "t" * 40, "device_id": "dev1"}),
    ("post", f"/api/v1/vehicles/{VID}/push/unified", {"endpoint": "https://up.example.com/x", "device_id": "dev1"}),
    ("get", f"/api/v1/vehicles/{VID}/push/subscriptions", None),
    ("post", f"/api/v1/vehicles/{VID}/push/email", {"email": "root@example.com"}),
    ("post", f"/api/v1/vehicles/{VID}/push/ntfy", {"topic": "rootstopic"}),
]


@pytest.mark.parametrize("method,path,body", OWNER_ONLY)
def test_notification_routes_stay_the_owners_under_a_grant(client, db, method, path, body):
    _, headers = _setup(db, granted=True)
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    response = getattr(client, method)(path, **kwargs)
    # 403 from the gate; a 422 would mean the body never reached it.
    assert response.status_code == 403, response.text
    db.expire_all()
    assert db.query(models_db.PushSubscription).count() == 0


# --- an admin owns no vehicle -----------------------------------------------------

def _create(client, headers, **extra):
    body = {"vehicle_id": "NEWCAR", "server_password": "a-long-password-1", "protocol": "v3", **extra}
    return client.post("/api/v1/vehicles", json=body, headers=headers)


def test_an_admin_cannot_register_a_vehicle_for_themselves(client, db):
    _, headers = _setup(db, granted=False)
    assert _create(client, headers).status_code == 400
    admin_id = db.query(models_db.User).filter_by(username="root").one().id
    assert _create(client, headers, owner_id=admin_id).status_code == 400
    db.expire_all()
    assert db.query(models_db.Vehicle).filter_by(vehicle_id="NEWCAR").count() == 0


def test_an_admin_registers_a_vehicle_for_a_user(client, db):
    _, headers = _setup(db, granted=False)
    bob_id = db.query(models_db.User).filter_by(username="bob").one().id
    response = _create(client, headers, owner_id=bob_id)
    assert response.status_code == 201, response.text
    assert response.json()["owner_username"] == "bob"


def test_an_owner_of_vehicles_cannot_be_made_admin(client, db):
    _, headers = _setup(db, granted=False)
    alice = db.query(models_db.User).filter_by(username="alice").one()
    response = client.put(f"/api/v1/users/{alice.id}", json={"is_admin": True}, headers=headers)
    assert response.status_code == 409, response.text
    db.refresh(alice)
    assert alice.is_admin is False


def test_a_user_without_vehicles_can_be_made_admin(client, db):
    _, headers = _setup(db, granted=False)
    carol = _user(db, "carol")
    response = client.put(f"/api/v1/users/{carol.id}", json={"is_admin": True}, headers=headers)
    assert response.status_code == 200, response.text


def test_the_list_records_the_admins_read(client, db):
    """The list carries each granted vehicle's position and status: a read of the
    owner's data, audited like the per-vehicle routes."""
    _, headers = _setup(db, granted=True)
    for _ in range(2):
        assert client.get("/api/v1/vehicles", headers=headers).status_code == 200
    db.expire_all()
    events = db.query(models_db.SecurityEvent).filter_by(event_type="support_access").all()
    assert len(events) == 1
    assert events[0].details["vehicle_id"] == VID


def test_an_owners_list_records_nothing(client, db):
    alice = _user(db, "alice")
    _vehicle(db, alice, VID, granted=True)
    _, key = crud.apikey.create_api_key(db=db, user_id=alice.id, name="alice key")
    assert client.get("/api/v1/vehicles", headers={"X-API-Key": key}).status_code == 200
    db.expire_all()
    assert db.query(models_db.SecurityEvent).filter_by(event_type="support_access").count() == 0


def _fake_send(monkeypatch):
    from app.models import api as models_api
    from app.routers.api import main as api_main

    sent = []

    async def fake_send(vehicle, command, *args):
        sent.append(command)
        return models_api.CommandResponse(vehicle_id=vehicle.vehicle_id, response_data="ok", success=True)

    monkeypatch.setattr(api_main, "send_command_to_vehicle", fake_send)
    return sent


def test_the_command_api_works_for_the_owner(client, db, monkeypatch):
    """It read `cmd_req.command`, a field the request model does not have: every
    command over the API was a 500, the owner's included."""
    sent = _fake_send(monkeypatch)
    alice = _user(db, "alice")
    _vehicle(db, alice, VID)
    _, key = crud.apikey.create_api_key(db=db, user_id=alice.id, name="alice key")
    response = client.post(f"/api/v1/command/{VID}", json={"command_code_with_args": "7,wakeup"},
                           headers={"X-API-Key": key})
    assert response.status_code == 200, response.text
    assert sent == ["7,wakeup"]


def test_the_command_api_under_a_grant_is_recorded_without_its_arguments(client, db, monkeypatch):
    sent = _fake_send(monkeypatch)
    _, headers = _setup(db, granted=True)
    response = client.post(f"/api/v1/command/{VID}", json={"command_code_with_args": "3,4,s3cr3t"},
                           headers=headers)
    assert response.status_code == 200, response.text
    assert sent == ["3,4,s3cr3t"]
    db.expire_all()
    events = db.query(models_db.SecurityEvent).filter_by(event_type="support_access").all()
    assert [e.details["command"] for e in events] == ["3"]
    assert "s3cr3t" not in str(events[0].details)


def test_the_command_api_without_a_grant_is_refused(client, db, monkeypatch):
    sent = _fake_send(monkeypatch)
    _, headers = _setup(db, granted=False)
    response = client.post(f"/api/v1/command/{VID}", json={"command_code_with_args": "7,wakeup"},
                           headers=headers)
    assert response.status_code == 403
    assert sent == []


@pytest.mark.parametrize("command,summary", [
    ("config set vehicle password s3cr3t", "config set"),
    ("7,config set vehicle password s3cr3t", "7,config set"),
    ("3,4,s3cr3t", "3"),
    ("41,+491701234567,hello", "41"),
    ("11", "11"),
    ("7,", "7,"),
    ("", ""),
    (None, ""),
])
def test_a_command_is_summarized_without_its_arguments(command, summary):
    assert support_mode.summarize_command(command) == summary


def _with_live_state(db, vehicle):
    vehicle.latest_location_msg = "L,52.520000,13.405000,90,34,1,1"
    vehicle.latest_status_msg = "S,80,K,0,0,stopped,standard,200,190,0,0,0,0,0,0,0,0"
    db.commit()


def test_an_update_without_a_grant_returns_no_live_state(client, db):
    """`PUT {}` answered with the full VehicleInfo — position, status, the module's
    address — to any admin: a read around the support gate, unaudited."""
    vehicle, headers = _setup(db, granted=False)
    _with_live_state(db, vehicle)
    response = client.put(f"/api/v1/vehicles/{vehicle.id}", json={}, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["vehicle_id"] == VID
    for field in ("latest_location_parsed", "latest_status_parsed", "latest_tpms_parsed",
                  "latest_diag_parsed", "address"):
        assert body[field] is None, field
    db.expire_all()
    assert db.query(models_db.SecurityEvent).filter_by(event_type="support_access").count() == 0


def test_an_update_under_a_grant_returns_the_live_state_audited(client, db):
    vehicle, headers = _setup(db, granted=True)
    _with_live_state(db, vehicle)
    response = client.put(f"/api/v1/vehicles/{vehicle.id}", json={}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["latest_location_parsed"] is not None
    db.expire_all()
    assert db.query(models_db.SecurityEvent).filter_by(event_type="support_access").count() == 1


def test_a_failed_audit_row_frees_its_throttle_slot(db, monkeypatch):
    """A row that could not be written must not silence the next quarter hour."""
    from app import security_events

    vehicle, _ = _setup(db, granted=True)
    admin = db.query(models_db.User).filter_by(username="root").one()
    real = security_events.security_event_logger.log_event
    calls = []

    def locked_once(**kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        return real(**kwargs)

    monkeypatch.setattr(security_events.security_event_logger, "log_event", locked_once)
    support_mode.record_support_access(admin, vehicle, "api")
    support_mode.record_support_access(admin, vehicle, "api")
    db.expire_all()
    assert len(calls) == 2
    assert db.query(models_db.SecurityEvent).filter_by(event_type="support_access").count() == 1
