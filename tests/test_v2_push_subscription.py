"""A V2 app's push token becomes a subscription, like every other target.

It used to be written to the vehicle-level `fcm_token`/`apns_token` columns only, which
the GUI never listed and the dispatcher only read as a fallback. Those columns are gone
(c6d7e8f9a0b1); a token that did not land in `push_subscriptions` now would reach
nobody.
"""
import asyncio
import types

import pytest

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.protocols.v2 import handlers
from app.services.charge_logger import models as _charge_logger_models  # noqa: F401  (Vehicle.charge_logs)
from app.utils.crypto import encrypt_data

SERVER_PASSWORD = "v2-server-password"


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
    db.query(models_db.User).delete()
    db.commit()
    yield


@pytest.fixture
def vehicle(db):
    user = models_db.User(username="owner", email="owner@example.com",
                          hashed_password="x", is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    vehicle = models_db.Vehicle(vehicle_id="CAR1", owner_id=user.id, protocol="both",
                                encrypted_server_password=encrypt_data(SERVER_PASSWORD))
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _subscribe(db, *, app_id="app-1", push_type="gcm", token="token-1",
               net_pass=SERVER_PASSWORD, vehicle_id="CAR1"):
    conn = types.SimpleNamespace(vehicle_id="CAR1")
    msg = types.SimpleNamespace(app_id=app_id, push_type=push_type, vehicle_id=vehicle_id,
                                net_pass=net_pass, push_key_value=token)
    asyncio.run(handlers._handle_app_push_subscription(conn, msg, db))


def _rows(db):
    db.expire_all()
    return sorted(
        (s.device_id, s.push_type, s.endpoint)
        for s in db.query(models_db.PushSubscription).all()
    )


def test_a_gcm_token_becomes_an_fcm_subscription(db, vehicle, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_FCM_TOKEN_FROM_V2", True)
    _subscribe(db)
    assert _rows(db) == [("v2:app-1", "fcm", "token-1")]


def test_a_new_token_from_the_same_app_replaces_its_row(db, vehicle, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_FCM_TOKEN_FROM_V2", True)
    _subscribe(db, token="token-1")
    _subscribe(db, token="token-2")
    assert _rows(db) == [("v2:app-1", "fcm", "token-2")]


def test_a_v2_app_leaves_an_api_registration_alone(db, vehicle, monkeypatch):
    """Keyed on the V2 app's own id: the two are separate devices."""
    monkeypatch.setattr(settings, "ALLOW_FCM_TOKEN_FROM_V2", True)
    db.add(models_db.PushSubscription(vehicle_id_fk=vehicle.id, device_id="phone",
                                      push_type="up", endpoint="https://up/phone"))
    db.commit()
    _subscribe(db)
    assert _rows(db) == [("phone", "up", "https://up/phone"), ("v2:app-1", "fcm", "token-1")]


@pytest.mark.parametrize("overrides", [
    {"net_pass": "wrong"},
    {"vehicle_id": "OTHER"},
    {"token": "   "},
    {"push_type": "apns"},  # ALLOW_APNS_TOKEN_FROM_V2 is off by default
])
def test_nothing_is_stored_without_a_valid_request(db, vehicle, monkeypatch, overrides):
    monkeypatch.setattr(settings, "ALLOW_FCM_TOKEN_FROM_V2", True)
    monkeypatch.setattr(settings, "ALLOW_APNS_TOKEN_FROM_V2", False)
    _subscribe(db, **overrides)
    assert _rows(db) == []


def test_the_setting_still_gates_fcm(db, vehicle, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_FCM_TOKEN_FROM_V2", False)
    _subscribe(db)
    assert _rows(db) == []
