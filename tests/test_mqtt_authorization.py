"""
Regression tests for C-1: cross-tenant data injection over MQTT.

Two independent layers were broken at once:

1. The broker ACL granted every API-key account `topic readwrite ovms/{username}/#`.
   The wildcard sits *after* the username, so it also matched the vehicle-id segment.
2. Both backend subscribers took the vehicle from the third topic segment and never
   looked at the second (owner) segment, verifying only that the vehicle existed.

Together: any registered user could create an API key and publish to
`ovms/<own-username>/<someone-elses-vehicle>/...` — forging position, charge state and
push notifications for a car they do not own. Each layer is tested separately, because
either one alone is enough to reopen the hole.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import db as models_db
from app.services.mqtt_auth_manager import MosquittoAuthManager
from app.utils import mqtt_topic_auth
from app.utils.crypto import encrypt_data


@pytest.fixture
def db_factory():
    """In-memory DB with two users, each owning one v3 vehicle."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    session = Session()
    alice = models_db.User(username="alice", email="alice@example.com", hashed_password="x", is_active=True)
    mallory = models_db.User(username="mallory", email="mallory@example.com", hashed_password="x", is_active=True)
    session.add_all([alice, mallory])
    session.flush()
    secret = encrypt_data("vehicle-password")
    session.add_all([
        models_db.Vehicle(vehicle_id="ALICECAR", owner_id=alice.id, protocol="v3",
                          encrypted_server_password=secret),
        models_db.Vehicle(vehicle_id="MALLORYCAR", owner_id=mallory.id, protocol="v3",
                          encrypted_server_password=secret),
    ])
    session.commit()
    session.close()

    mqtt_topic_auth.clear_cache()
    yield Session
    mqtt_topic_auth.clear_cache()


# --- Layer 2: the subscribers must bind vehicle to owner -------------------------

def test_owner_may_publish_for_own_vehicle(db_factory):
    assert mqtt_topic_auth.topic_owner_matches(db_factory, "alice", "ALICECAR") is True


def test_cross_tenant_publish_is_rejected(db_factory):
    """The actual attack: mallory publishing under her own prefix for alice's car."""
    assert mqtt_topic_auth.topic_owner_matches(db_factory, "mallory", "ALICECAR") is False


def test_unknown_vehicle_is_rejected(db_factory):
    assert mqtt_topic_auth.topic_owner_matches(db_factory, "alice", "NOSUCHCAR") is False


def test_rejection_is_not_poisoned_by_the_cache(db_factory):
    """A denied attempt must not create a cache entry that later allows the attacker."""
    assert mqtt_topic_auth.topic_owner_matches(db_factory, "mallory", "ALICECAR") is False
    assert mqtt_topic_auth.topic_owner_matches(db_factory, "alice", "ALICECAR") is True
    assert mqtt_topic_auth.topic_owner_matches(db_factory, "mallory", "ALICECAR") is False


def test_username_comparison_is_exact(db_factory):
    """No prefix or case slippage: 'alic' or 'ALICE' must not pass for 'alice'."""
    for impostor in ("alic", "alicex", "ALICE", " alice"):
        assert mqtt_topic_auth.topic_owner_matches(db_factory, impostor, "ALICECAR") is False


# --- Layer 1: the generated ACL must not contain a wildcard after the username ---

@pytest.fixture
def acl_lines(db_factory, tmp_path):
    manager = MosquittoAuthManager(
        passwd_path=str(tmp_path / "passwd"),
        acl_path=str(tmp_path / "acl"),
    )
    session = db_factory()
    try:
        session.add(models_db.ApiKey(
            key_prefix="mallorykey",
            hashed_key="deadbeef",
            name="mallory's key",
            user_id=session.query(models_db.User).filter_by(username="mallory").one().id,
            is_active=True,
        ))
        session.commit()
        assert manager.regenerate_acl_file(session) is True
    finally:
        session.close()
    return (tmp_path / "acl").read_text().splitlines()


def _rules_for(acl_lines, account):
    """
    The rules belonging to one `user <account>` block.

    Matching against the flat file was fine while every account had the same blanket
    rule, but it stopped distinguishing accounts once API keys and vehicles were
    granted different things: an assertion about the API key silently started passing
    on the *vehicle* account's line, which carries the same topic.
    """
    rules, inside = [], False
    for line in acl_lines:
        stripped = line.strip()
        if stripped.startswith("user "):
            inside = stripped == f"user {account}"
            continue
        if inside and stripped.startswith("topic "):
            rules.append(stripped)
    return rules


def _verb_and_topic(rule):
    _, verb, topic = rule.split(" ", 2)
    return verb, topic


def test_api_key_acl_has_no_wildcard_directly_after_username(acl_lines):
    for line in acl_lines:
        assert not line.strip().endswith("/#") or line.count("/") >= 3, (
            f"ACL rule {line!r} wildcards the vehicle-id segment"
        )
    assert "topic readwrite ovms/mallory/#" not in acl_lines


def test_api_key_write_rules_never_wildcard_the_vehicle_segment(acl_lines):
    """
    The precise C-1 property, now that the account also holds a deliberate wildcard
    *read* rule for vehicle discovery.

    Injection was the whole finding: a wildcard vehicle segment on a **write** rule is
    what let an account publish into a car it did not own. A wildcard on a read rule
    is a different question — the username segment stays literal, so it cannot reach
    another tenant, and nothing but this user's own vehicles can publish there.
    """
    for rule in _rules_for(acl_lines, "mallorykey"):
        verb, topic = _verb_and_topic(rule)
        if verb not in ("write", "readwrite"):
            continue
        segments = topic.split("/")
        vehicle_segment = segments[2] if len(segments) > 2 else ""
        assert vehicle_segment not in ("+", "#"), (
            f"write rule {rule!r} wildcards the vehicle-id segment"
        )


def test_api_key_acl_is_scoped_to_owned_vehicles_only(acl_lines):
    rules = _rules_for(acl_lines, "mallorykey")
    assert rules, "the API key account has no rules at all"
    assert any("ovms/mallory/MALLORYCAR/" in rule for rule in rules)
    # The whole point: mallory's key must get no rule for alice's car.
    assert not any("ALICECAR" in rule for rule in rules)


def test_vehicle_accounts_are_still_scoped_to_their_own_topic(acl_lines):
    assert _rules_for(acl_lines, "ALICECAR") == ["topic readwrite ovms/alice/ALICECAR/#"]
    assert _rules_for(acl_lines, "MALLORYCAR") == ["topic readwrite ovms/mallory/MALLORYCAR/#"]


# --- API keys consume, vehicles produce -----------------------------------------
#
# A blanket readwrite let a leaked device key publish into the branches the *car*
# owns. Forging is worth more than reading: a notify/ publish is a push message to
# the owner's phone with perfect provenance, and a metric/ publish writes fake GPS
# and charge state into the history and into Karto's trip records.


def test_api_key_may_not_publish_notifications(acl_lines):
    rules = _rules_for(acl_lines, "mallorykey")
    writable = [r for r in rules if r.startswith(("topic write", "topic readwrite"))]

    assert writable, "the API key account cannot publish anything at all"
    assert not any("notify" in r for r in writable)
    assert not any(
        r.endswith("MALLORYCAR/#") for r in writable
    ), "a blanket write on the vehicle subtree still covers notify/"


def test_api_key_may_not_publish_metrics_or_events(acl_lines):
    """Same rule, the other two car-owned branches."""
    rules = _rules_for(acl_lines, "mallorykey")
    writable = [r for r in rules if r.startswith(("topic write", "topic readwrite"))]

    for branch in ("metric", "event"):
        assert not any(branch in r for r in writable)


def test_api_key_may_still_publish_commands(acl_lines):
    """
    The app publishes command/, request/ and the active flag, all under client/.
    Tightening the write rule past this point would break every client.
    """
    rules = _rules_for(acl_lines, "mallorykey")

    assert "topic write ovms/mallory/MALLORYCAR/client/#" in rules


def test_api_key_may_still_read_the_whole_vehicle_subtree(acl_lines):
    """The app subscribes to metric/#, event/#, notify/# and its own response topic."""
    rules = _rules_for(acl_lines, "mallorykey")

    assert "topic read ovms/mallory/MALLORYCAR/#" in rules


# --- Vehicle discovery in the app ------------------------------------------------
#
# The app subscribes to the version metric across all vehicle ids, publishes
# "server v3 update all" so the modules announce themselves, and collects the ids
# that answer. Neither topic names a concrete vehicle, so enumerating the owned ones
# (C-1) stopped covering them and the feature would silently stop finding cars.


def test_api_key_may_subscribe_to_the_discovery_metric(acl_lines):
    rules = _rules_for(acl_lines, "mallorykey")

    assert "topic read ovms/mallory/+/metric/m/version" in rules


def test_api_key_may_publish_the_discovery_command(acl_lines):
    rules = _rules_for(acl_lines, "mallorykey")

    assert "topic write ovms/mallory/discovery/client/#" in rules


def test_discovery_rules_stay_inside_the_owner_prefix(acl_lines):
    """
    The reason the wildcard is acceptable here: the username segment is literal, so
    discovery can never surface another tenant's vehicle.
    """
    for rule in _rules_for(acl_lines, "mallorykey"):
        _, topic = _verb_and_topic(rule)
        assert topic.split("/")[1] == "mallory", f"{rule!r} escapes the owner prefix"


def test_discovery_does_not_grant_writes_on_real_vehicle_branches(acl_lines):
    """
    The discovery write must stay under the non-existent `discovery` vehicle id. If it
    widened to `ovms/{user}/+/client/#` it would hand back cross-vehicle command
    injection for every car the user owns.
    """
    rules = _rules_for(acl_lines, "mallorykey")
    writable = [r for r in rules if _verb_and_topic(r)[0] in ("write", "readwrite")]

    for rule in writable:
        _, topic = _verb_and_topic(rule)
        assert "/client/" in topic or topic.endswith("/client/#"), (
            f"{rule!r} grants write outside the client subtree"
        )


def test_vehicle_module_may_still_publish_notifications(acl_lines):
    """The car is the party that legitimately produces notify/ — it must keep write."""
    rules = _rules_for(acl_lines, "MALLORYCAR")

    assert any(
        r.startswith("topic readwrite") and r.endswith("MALLORYCAR/#") for r in rules
    ), "the vehicle module lost its ability to publish notifications"


def test_new_broker_files_are_not_world_readable(db_factory, tmp_path):
    """M-1: the passwd file holds PBKDF2 hashes for every vehicle and API key."""
    manager = MosquittoAuthManager(passwd_path=str(tmp_path / "passwd"), acl_path=str(tmp_path / "acl"))
    session = db_factory()
    try:
        manager.regenerate_acl_file(session)
    finally:
        session.close()
    mode = (tmp_path / "acl").stat().st_mode & 0o777
    assert mode & 0o007 == 0, f"broker file is world-accessible (mode {mode:o})"


def test_existing_file_mode_is_preserved_across_rewrites(db_factory, tmp_path):
    """
    An operator's chmod/chgrp must survive a sync. The broker often runs as its own
    user and needs group read, so we must not force our own mode onto an existing file —
    the original bug was the opposite: every rewrite reset the mode back to 0644.
    """
    import os

    acl = tmp_path / "acl"
    acl.write_text("# placeholder\n")
    os.chmod(acl, 0o600)

    manager = MosquittoAuthManager(passwd_path=str(tmp_path / "passwd"), acl_path=str(acl))
    session = db_factory()
    try:
        manager.regenerate_acl_file(session)
    finally:
        session.close()

    assert acl.stat().st_mode & 0o777 == 0o600, "hand-tightened permissions were reset by a sync"
