"""
Support mode in the broker ACL (MosquittoAuthManager.regenerate_acl_file).

While an owner's grant runs, every admin's API key reaches the vehicle exactly as
the owner's key does — read its subtree, write its `client/` commands — under the
owner's prefix. Never readwrite, never a wildcard vehicle, never the module's
notify/metric/event topics, never an internal key, and nothing once it ends.
"""

import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.services.charge_logger.models  # noqa: F401  (Vehicle's relationships name its models)
from app.crud import user as crud_user
from app.database import Base
from app.models import api as models_api
from app.models import db as models_db
from app.services.mqtt_auth_manager import MosquittoAuthManager


def _until(hours):
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    alice = models_db.User(username="alice", email="a@example.com", hashed_password="x", is_active=True)
    bob = models_db.User(username="bob", email="b@example.com", hashed_password="x", is_active=True)
    root = models_db.User(username="root", email="r@example.com", hashed_password="x", is_active=True, is_admin=True)
    s.add_all([alice, bob, root])
    s.flush()
    s.add_all([
        models_db.Vehicle(vehicle_id="ALICECAR", owner_id=alice.id, protocol="v3", encrypted_server_password=b"x"),
        models_db.Vehicle(vehicle_id="BOBCAR", owner_id=bob.id, protocol="v3", encrypted_server_password=b"x"),
        models_db.ApiKey(key_prefix="rootkey1", hashed_key="h1", name="root's key", user_id=root.id, is_active=True),
        models_db.ApiKey(key_prefix="bobkey01", hashed_key="h2", name="bob's key", user_id=bob.id, is_active=True),
        models_db.ApiKey(key_prefix="rootint1", hashed_key="h3", name="temp-karto-delete-x", user_id=root.id,
                         is_active=True),
    ])
    s.commit()
    yield s
    s.close()


def _grant(session, vid="ALICECAR", hours=1, granted_by=None):
    vehicle = session.query(models_db.Vehicle).filter_by(vehicle_id=vid).one()
    vehicle.support_until = _until(hours)
    vehicle.support_granted_by_id = vehicle.owner_id if granted_by is None else granted_by
    session.commit()


def _acl(session, tmp_path):
    manager = MosquittoAuthManager(passwd_path=str(tmp_path / "passwd"), acl_path=str(tmp_path / "acl"))
    assert manager.regenerate_acl_file(session) is True
    return (tmp_path / "acl").read_text().splitlines()


def _rules_for(lines, account):
    rules, inside = [], False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("user "):
            inside = stripped == f"user {account}"
            continue
        if inside and stripped.startswith("topic "):
            rules.append(stripped)
    return rules


def test_no_grant_no_block_for_an_admin_without_vehicles(session, tmp_path):
    assert _rules_for(_acl(session, tmp_path), "rootkey1") == []


def test_a_grant_gives_the_admin_key_the_owners_rights(session, tmp_path):
    _grant(session)
    rules = _rules_for(_acl(session, tmp_path), "rootkey1")
    assert rules == [
        "topic read ovms/alice/ALICECAR/#",
        "topic write ovms/alice/ALICECAR/client/#",
    ]


def test_the_grant_never_writes_module_topics(session, tmp_path):
    _grant(session)
    for rule in _rules_for(_acl(session, tmp_path), "rootkey1"):
        verb, topic = rule.split(" ", 2)[1:]
        assert verb in ("read", "write")
        if verb == "write":
            assert "/client/" in topic
            assert not any(part in topic for part in ("/notify", "/metric", "/event"))


def test_only_the_granted_vehicle(session, tmp_path):
    _grant(session)
    rules = " ".join(_rules_for(_acl(session, tmp_path), "rootkey1"))
    assert "BOBCAR" not in rules


def test_non_admin_keys_get_no_grant(session, tmp_path):
    _grant(session)
    rules = " ".join(_rules_for(_acl(session, tmp_path), "bobkey01"))
    assert "ALICECAR" not in rules
    assert "BOBCAR" in rules


def test_internal_keys_get_no_grant(session, tmp_path):
    _grant(session)
    assert _rules_for(_acl(session, tmp_path), "rootint1") == []


def test_an_expired_grant_gives_nothing(session, tmp_path):
    _grant(session, hours=-1)
    assert _rules_for(_acl(session, tmp_path), "rootkey1") == []


def test_a_grant_by_someone_else_gives_nothing(session, tmp_path):
    _grant(session, granted_by=999)
    assert _rules_for(_acl(session, tmp_path), "rootkey1") == []


def test_an_inactive_admin_gets_nothing(session, tmp_path):
    _grant(session)
    session.query(models_db.User).filter_by(username="root").one().is_active = False
    session.commit()
    assert _rules_for(_acl(session, tmp_path), "rootkey1") == []


def test_a_change_of_admin_rights_queues_an_acl_rebuild(session, monkeypatch):
    calls = []
    monkeypatch.setattr(crud_user.mqtt_sync_worker, "mark_acl_dirty", lambda: calls.append("acl"))
    monkeypatch.setattr(crud_user, "_end_browser_sessions", lambda *a, **k: None)
    bob = session.query(models_db.User).filter_by(username="bob").one()
    crud_user.update_user(session, bob, models_api.UserUpdate(is_admin=True))
    assert calls == ["acl"]
