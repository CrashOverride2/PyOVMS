"""
A charge log that is not there for the caller is one answer: 404 `charge_log_not_found`.

- Another account's charge log is answered exactly like one that does not exist — a 403
  for it confirmed that the id exists, a membership oracle over UUIDs that turn up in
  shared links and logs. Karto answers trips the same way.
- The `detail` is machine-readable, so the app can tell it from a 404 that is not this
  handler's (an unrouted path, a proxy) and count a delete answered with it as done.
  Apps shipped before read the status code alone, which is unchanged.
- Every route addressed by a charge log id goes through it: details, delete, GPX, KML.
"""

import datetime
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import db as models_db
from app.services.charge_logger import api as charge_api
from app.services.charge_logger import models as charge_models

UTC = datetime.timezone.utc


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _user(db, name):
    user = models_db.User(username=name, email=f"{name}@example.invalid",
                          hashed_password="x", is_active=True, is_admin=False)
    db.add(user)
    db.commit()
    return user


def _charge_of(db, owner):
    vehicle = models_db.Vehicle(vehicle_id=f"CAR{owner.id}", owner_id=owner.id, protocol="v3",
                                encrypted_server_password=b"x", enable_charge_logging=True)
    db.add(vehicle)
    db.commit()
    start = datetime.datetime(2026, 10, 1, 8, 0, tzinfo=UTC)
    log = charge_models.ChargeLog(vehicle_id_fk=vehicle.id, start_time=start,
                                  end_time=start + datetime.timedelta(hours=1),
                                  start_soc=20.0, end_soc=80.0,
                                  start_latitude=49.0, start_longitude=8.0)
    db.add(log)
    db.commit()
    return log.id


ROUTES = {
    "details": lambda db, log_id, user: charge_api.get_charge_log_details(log_id, db=db, current_user=user),
    "delete": lambda db, log_id, user: charge_api.delete_charge_log(log_id, db=db, current_user=user),
    "gpx": lambda db, log_id, user: charge_api.export_charge_location_gpx(log_id, db=db, current_user=user),
    "kml": lambda db, log_id, user: charge_api.export_charge_location_kml(log_id, db=db, current_user=user),
}


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_another_accounts_charge_log_is_answered_as_one_that_does_not_exist(db, route):
    owner = _user(db, "owner")
    stranger = _user(db, "stranger")
    log_id = _charge_of(db, owner)
    call = ROUTES[route]

    with pytest.raises(HTTPException) as foreign:
        call(db, log_id, SimpleNamespace(id=stranger.id))
    with pytest.raises(HTTPException) as missing:
        call(db, uuid.uuid4(), SimpleNamespace(id=stranger.id))

    assert (foreign.value.status_code, foreign.value.detail) == (404, "charge_log_not_found")
    assert (missing.value.status_code, missing.value.detail) == (404, "charge_log_not_found")
    # Nothing was done to the owner's row.
    db.expire_all()
    assert db.query(charge_models.ChargeLog).filter_by(id=log_id).one_or_none() is not None


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_the_owner_still_reaches_it(db, route):
    owner = _user(db, "owner")
    log_id = _charge_of(db, owner)
    result = ROUTES[route](db, log_id, SimpleNamespace(id=owner.id))
    assert result is not None
