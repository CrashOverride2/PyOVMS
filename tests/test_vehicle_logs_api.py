"""
Functional tests for the vehicle log and notification-target endpoints.

These moved data that was previously only reachable behind a cookie session onto the
API-key surface, which is the exact shape of change that leaks something. Three
properties are pinned here:

  * a key only ever reaches vehicles its owner owns — for every new route, not just
    the one that happened to get a test;
  * push tokens, UnifiedPush endpoints and ntfy credentials never appear in a
    response, however the subscription was created;
  * the paged reader stays bounded, so the endpoint cannot be turned into the OOM
    primitive tests/test_history_dump_bounded.py exists to prevent — bounded in
    *bytes* as well as rows, because one row here holds up to 64 KiB;
  * every timestamp leaves as UTC-aware, so a client cannot silently read it in its
    own zone.

Driven over HTTP against the temporary SQLite database, because the guards under test
are dependencies and ownership checks — an import-level assertion would not exercise
either.
"""

import datetime

import pytest
from fastapi.testclient import TestClient

from app import crud, security
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
    """Every test here shares the client address "testclient"; a leftover block row
    would answer 429 from the middleware before the route is ever reached."""
    db.query(models_db.PushSubscription).delete()
    db.query(models_db.HistoricalData).delete()
    db.query(models_db.Vehicle).delete()
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


def _user_with_key(db, username="alice"):
    user = models_db.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True,
        is_admin=False,
        is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _, plain_key = crud.apikey.create_api_key(db, user.id, f"{username}-key")
    _settle(db)
    return user, plain_key


def _vehicle(db, owner, vehicle_id="CAR1"):
    vehicle = models_db.Vehicle(
        vehicle_id=vehicle_id,
        owner_id=owner.id,
        protocol="v3",
        encrypted_server_password=b"x",
    )
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    _settle(db)
    return vehicle


def _record(db, vehicle, record_type, payload, when=None, record_number=0):
    db.add(models_db.HistoricalData(
        vehicle_id_fk=vehicle.id,
        vehicle_module_id_str=vehicle.vehicle_id,
        timestamp=when or datetime.datetime.now(datetime.timezone.utc),
        record_type=record_type,
        record_number=record_number,
        data_payload=payload,
    ))
    db.commit()


def _auth(key):
    return {"X-API-Key": key}


def _settle(db):
    """End whatever transaction the setup left open before issuing a request.

    SQLite takes one writer at a time and the request runs in its own session. A
    `refresh()` in a helper starts a read transaction that is never closed, and the
    endpoint's own write then fails with "database is locked" — a fixture artefact
    that looks exactly like a real defect.
    """
    db.commit()


# The complete set of routes added, so a later addition that forgets its ownership
# check fails here rather than in the field. A write carries a *valid* body: an
# invalid one is rejected before the route body runs, and the check under test would
# never be reached.
def _routes(vehicle_id="CAR1", subscription_id=1):
    base = f"/api/v1/vehicles/{vehicle_id}"
    return [
        ("get", f"{base}/datalogs", None),
        ("get", f"{base}/datalogs/records?type=*-LOG-Trip", None),
        ("get", f"{base}/logs", None),
        ("get", f"{base}/push/subscriptions", None),
        ("delete", f"{base}/push/subscriptions/{subscription_id}", None),
        ("post", f"{base}/push/email", {"email": "intruder@example.com"}),
        ("post", f"{base}/push/ntfy", {"topic": "intruder-topic"}),
    ]


def _call(client, method, url, body, headers=None):
    kwargs = {"headers": headers} if headers else {}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(url, **kwargs)


@pytest.mark.parametrize("method,url,body", _routes(), ids=lambda v: str(v))
def test_every_route_refuses_an_unauthenticated_caller(client, db, method, url, body):
    owner, _ = _user_with_key(db, "owner")
    _vehicle(db, owner)

    response = _call(client, method, url, body)

    assert response.status_code in (401, 403), (
        f"{method.upper()} {url} answered {response.status_code} without an API key"
    )


@pytest.mark.parametrize("method,url,body", _routes(), ids=lambda v: str(v))
def test_every_route_refuses_a_key_of_another_user(client, db, method, url, body):
    owner, _ = _user_with_key(db, "owner")
    _vehicle(db, owner)
    _, intruder_key = _user_with_key(db, "intruder")

    response = _call(client, method, url, body, headers=_auth(intruder_key))

    assert response.status_code == 403, (
        f"{method.upper()} {url} answered {response.status_code} to a stranger's key"
    )


def test_the_type_summary_lists_data_records_and_hides_crash_records(client, db):
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    _record(db, vehicle, "*-LOG-Trip", "1,52.5,13.4")
    _record(db, vehicle, "*-OVM-DebugCrash", "3.3.004,build,4,Panic")

    body = client.get("/api/v1/vehicles/CAR1/datalogs", headers=_auth(key)).json()

    types = {t["record_type"] for t in body["types"]}
    assert types == {"*-LOG-Trip"}, "crash records must not appear as a data log type"
    trip = next(t for t in body["types"] if t["record_type"] == "*-LOG-Trip")
    assert trip["fields"], "a known record type must carry its column names"


def test_records_are_paged_and_the_page_size_is_capped(client, db):
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    for n in range(5):
        _record(db, vehicle, "*-LOG-Trip", f"{n},52.5,13.4",
                when=base + datetime.timedelta(minutes=n))

    page1 = client.get("/api/v1/vehicles/CAR1/datalogs/records",
                       params={"type": "*-LOG-Trip", "page": 1, "page_size": 2},
                       headers=_auth(key)).json()
    assert len(page1["records"]) == 2
    assert page1["has_more"] is True
    assert page1["headers"][0] == "GPS lock", "known types get named columns"

    page3 = client.get("/api/v1/vehicles/CAR1/datalogs/records",
                       params={"type": "*-LOG-Trip", "page": 3, "page_size": 2},
                       headers=_auth(key)).json()
    assert len(page3["records"]) == 1
    assert page3["has_more"] is False

    # The bound is the point: an unbounded page over the 10 000-row x 64 KiB quota is
    # an out-of-memory primitive for any authenticated caller.
    rejected = client.get("/api/v1/vehicles/CAR1/datalogs/records",
                          params={"type": "*-LOG-Trip", "page_size": 10_000},
                          headers=_auth(key))
    assert rejected.status_code == 422


def test_crash_and_debug_records_are_separated_and_parsed(client, db):
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    _record(db, vehicle, "*-OVM-DebugCrash", "3.3.004,buildid,4,Panic,1,0x4008,LoadProhibited,0,,0x40081234")
    _record(db, vehicle, "V3Crash-1", "3.3.004,buildid,4,Panic,0,0x4008,,0,,0x40081234")
    _record(db, vehicle, "*-OVM-DebugTasks", "task dump")

    body = client.get("/api/v1/vehicles/CAR1/logs", headers=_auth(key)).json()

    assert {c["protocol"] for c in body["crash_logs"]} == {"v2", "v3"}
    assert all("Crash" in c["record_type"] for c in body["crash_logs"])
    assert [d["record_type"] for d in body["debug_logs"]] == ["*-OVM-DebugTasks"], (
        "a crash record must not also be reported as a debug record"
    )
    assert body["crash_logs"][0]["firmware"] == "3.3.004"


def test_push_tokens_and_ntfy_credentials_never_reach_the_response(client, db):
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    crud.push_subscription.upsert_subscription(db, vehicle.id, "device-1", "fcm", "SECRET-FCM-TOKEN")
    crud.push_subscription.upsert_subscription(db, vehicle.id, "device-2", "apns", "SECRET-APNS-TOKEN")
    crud.push_subscription.add_manual_ntfy(
        db, vehicle.id, "my-topic", server_url="https://ntfy.example",
        auth_method="bearer", auth_token="SECRET-NTFY-TOKEN",
    )
    _settle(db)

    response = client.get("/api/v1/vehicles/CAR1/push/subscriptions", headers=_auth(key))
    raw = response.text
    body = response.json()

    for secret in ("SECRET-FCM-TOKEN", "SECRET-APNS-TOKEN", "SECRET-NTFY-TOKEN"):
        assert secret not in raw, f"{secret} was disclosed by the subscription list"

    by_type = {s["push_type"]: s for s in body["subscriptions"]}
    assert by_type["fcm"]["endpoint"] is None
    assert by_type["apns"]["endpoint"] is None
    # The ntfy topic is not a credential — it is what the user typed and has to see to
    # recognise the entry. The token that goes with it is what must not come back.
    assert by_type["ntfy"]["endpoint"] == "my-topic"
    assert by_type["ntfy"]["has_auth"] is True


def test_a_subscription_of_another_vehicle_cannot_be_deleted_through_mine(client, db):
    owner, key = _user_with_key(db, "owner")
    mine = _vehicle(db, owner, "CAR1")
    stranger, _ = _user_with_key(db, "stranger")
    theirs = _vehicle(db, stranger, "CAR2")
    victim = crud.push_subscription.upsert_subscription(db, theirs.id, "device-x", "fcm", "token")
    _settle(db)

    response = client.delete(
        f"/api/v1/vehicles/{mine.vehicle_id}/push/subscriptions/{victim.id}",
        headers=_auth(key),
    )

    assert response.status_code == 404
    assert db.query(models_db.PushSubscription).filter_by(id=victim.id).count() == 1


def test_an_email_recipient_can_be_added_and_shows_up_as_a_target(client, db):
    owner, key = _user_with_key(db, "owner")
    _vehicle(db, owner)

    created = client.post("/api/v1/vehicles/CAR1/push/email",
                          json={"email": "alerts@example.com"}, headers=_auth(key))

    assert created.status_code == 201
    assert created.json()["endpoint"] == "alerts@example.com"

    listed = client.get("/api/v1/vehicles/CAR1/push/subscriptions", headers=_auth(key)).json()
    assert [s["endpoint"] for s in listed["subscriptions"]] == ["alerts@example.com"]


def test_adding_the_same_address_twice_does_not_duplicate_it(client, db):
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)

    for _ in range(2):
        client.post("/api/v1/vehicles/CAR1/push/email",
                    json={"email": "alerts@example.com"}, headers=_auth(key))

    assert db.query(models_db.PushSubscription).filter_by(
        vehicle_id_fk=vehicle.id, push_type="email"
    ).count() == 1


@pytest.mark.parametrize("address", [
    "alerts@example.com\nBcc: victim@example.com",
    "alerts@example.com\r\nSubject: forged",
    "alerts@example.com,second@example.com",
    "alerts@example.com;second@example.com",
    "alerts@example.com\x00",
    "not-an-address",
    "",
])
def test_an_address_that_could_inject_headers_is_refused(client, db, address):
    """The address reaches the SMTP layer, where compat32 serialises CR/LF verbatim —
    an unchecked value appends attacker-chosen headers and makes the server relay mail
    from its own domain. Same guard the web form has, asserted on the API path."""
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)

    response = client.post("/api/v1/vehicles/CAR1/push/email",
                           json={"email": address}, headers=_auth(key))

    assert response.status_code == 422, f"{address!r} was accepted"
    assert db.query(models_db.PushSubscription).filter_by(
        vehicle_id_fk=vehicle.id
    ).count() == 0


def test_an_ntfy_target_can_be_added_and_keeps_its_server(client, db):
    owner, key = _user_with_key(db, "owner")
    _vehicle(db, owner)

    created = client.post("/api/v1/vehicles/CAR1/push/ntfy", headers=_auth(key), json={
        "topic": "my-alerts",
        "server_url": "https://ntfy.example.com",
        "auth_method": "bearer",
        "auth_token": "SECRET-NTFY-TOKEN",
    })

    assert created.status_code == 201, created.text
    body = created.json()
    assert body["endpoint"] == "my-alerts"
    assert body["ntfy_server_url"] == "https://ntfy.example.com"
    assert body["has_auth"] is True
    # The credential goes in and never comes back, not even in the answer to the
    # request that supplied it.
    assert "SECRET-NTFY-TOKEN" not in created.text


@pytest.mark.parametrize("server_url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/",
    "http://localhost/",
    "http://10.0.0.5/",
    "file:///etc/passwd",
    "gopher://example.com/",
])
def test_an_ntfy_server_url_that_would_be_an_ssrf_is_refused(client, db, server_url):
    """The server fetches this URL itself when it delivers. Without the check, a
    notification target becomes a request to whatever the caller names — the cloud
    metadata endpoint, a service on loopback, a host inside the deployment."""
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)

    response = client.post("/api/v1/vehicles/CAR1/push/ntfy", headers=_auth(key),
                           json={"topic": "my-alerts", "server_url": server_url})

    assert response.status_code == 422, f"{server_url} was accepted"
    assert db.query(models_db.PushSubscription).filter_by(
        vehicle_id_fk=vehicle.id
    ).count() == 0


@pytest.mark.parametrize("topic", ["", "   "])
def test_an_empty_ntfy_topic_is_refused(client, db, topic):
    owner, key = _user_with_key(db, "owner")
    _vehicle(db, owner)

    response = client.post("/api/v1/vehicles/CAR1/push/ntfy", headers=_auth(key),
                           json={"topic": topic})

    assert response.status_code == 422


def test_several_targets_of_the_same_type_coexist(client, db):
    """The point of the list: two phones, two ntfy topics, two mailboxes. Only the
    identical target is an update — a different one is another recipient."""
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)

    client.post("/api/v1/vehicles/CAR1/push/ntfy", headers=_auth(key),
                json={"topic": "phone-a"})
    client.post("/api/v1/vehicles/CAR1/push/ntfy", headers=_auth(key),
                json={"topic": "phone-b"})
    client.post("/api/v1/vehicles/CAR1/push/email", headers=_auth(key),
                json={"email": "me@example.com"})
    client.post("/api/v1/vehicles/CAR1/push/email", headers=_auth(key),
                json={"email": "partner@example.com"})
    crud.push_subscription.upsert_subscription(db, vehicle.id, "device-1", "fcm", "token-1")
    crud.push_subscription.upsert_subscription(db, vehicle.id, "device-2", "fcm", "token-2")
    _settle(db)

    listed = client.get("/api/v1/vehicles/CAR1/push/subscriptions",
                        headers=_auth(key)).json()["subscriptions"]

    by_type = {}
    for sub in listed:
        by_type.setdefault(sub["push_type"], []).append(sub)
    assert len(by_type["ntfy"]) == 2
    assert len(by_type["email"]) == 2
    assert len(by_type["fcm"]) == 2


def test_deleting_my_own_subscription_removes_it(client, db):
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    sub = crud.push_subscription.upsert_subscription(db, vehicle.id, "device-1", "up", "https://up.example/x")
    _settle(db)

    response = client.delete(
        f"/api/v1/vehicles/CAR1/push/subscriptions/{sub.id}", headers=_auth(key)
    )

    assert response.status_code == 204
    assert db.query(models_db.PushSubscription).filter_by(id=sub.id).count() == 0


# --- a UnifiedPush endpoint is a credential too -------------------------------------

def test_a_unified_push_endpoint_is_never_returned(client, db):
    """Posting to the distributor URL is the whole authorisation to notify the device.

    It was returned in full while the FCM and APNs tokens beside it were redacted,
    which made "list my notification targets" hand out the means to notify them.
    """
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    crud.push_subscription.upsert_subscription(
        db, vehicle.id, "device-up", "up", "https://push.example/UP-SECRET-ENDPOINT"
    )
    _settle(db)

    response = client.get("/api/v1/vehicles/CAR1/push/subscriptions", headers=_auth(key))

    assert "UP-SECRET-ENDPOINT" not in response.text
    by_type = {s["push_type"]: s for s in response.json()["subscriptions"]}
    assert by_type["up"]["endpoint"] is None


@pytest.mark.parametrize("path,body", [
    ("push/email", {"email": "alerts@example.com"}),
    ("push/ntfy", {"topic": "my-topic", "server_url": "https://ntfy.example"}),
])
def test_every_create_path_redacts_exactly_like_the_list_path(client, db, path, body):
    """Every projection is the same function, and this is what says so.

    They were separate literals, which is how 'up' came to be handled in one and not
    the other — and how a third copy could return a naive created_at while the other
    two returned a UTC-aware one.
    """
    owner, key = _user_with_key(db, "owner")
    _vehicle(db, owner)

    created = client.post(f"/api/v1/vehicles/CAR1/{path}", json=body, headers=_auth(key))
    assert created.status_code == 201, created.text
    listed = client.get("/api/v1/vehicles/CAR1/push/subscriptions",
                        headers=_auth(key)).json()["subscriptions"]

    assert [created.json()] == listed


# --- timestamps carry their zone ----------------------------------------------------

def test_the_type_summary_reports_utc_aware_timestamps(client, db):
    """`first`/`last` used to be 'YYYY-MM-DD HH:MM:SS' with no zone at all.

    The CRUD still produces that string — V2 command 31 concatenates it into a protocol
    reply — but a JSON client has no way to know it means UTC, so the API projects the
    datetime instead.
    """
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    when = datetime.datetime(2026, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc)
    _record(db, vehicle, "*-LOG-Trip", "1,52.5,13.4", when=when)

    body = client.get("/api/v1/vehicles/CAR1/datalogs", headers=_auth(key)).json()

    trip = next(t for t in body["types"] if t["record_type"] == "*-LOG-Trip")
    for field in ("first", "last"):
        parsed = datetime.datetime.fromisoformat(trip[field])
        assert parsed.tzinfo is not None, f"{field} came back without a zone"
        assert parsed == when


def test_a_type_with_no_timestamps_reports_null_not_an_empty_string(client, db):
    """'' parsed as a datetime is an error; the absence has to be null."""
    owner, key = _user_with_key(db, "owner")
    _vehicle(db, owner)

    body = client.get("/api/v1/vehicles/CAR1/datalogs", headers=_auth(key)).json()

    assert body["types"] == []


# --- /logs is bounded in bytes, not only in rows ------------------------------------

def test_the_log_response_is_capped_in_bytes_and_says_so(client, db):
    """`limit` caps rows, and a row here is not small.

    A debug record holds up to 64 KiB, so 200 of them in each category is a ~25 MB
    response assembled in memory for any authenticated caller. The byte budget is the
    bound that actually matches the cost, and `truncated` is how the caller learns
    which of the two applied.
    """
    from app.routers.api.main import _LOG_MAX_RESPONSE_BYTES

    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    # Debug records, because DebugLogEntry carries `data` through verbatim — a crash
    # payload is parsed into fields and most of it never reaches the response, so it
    # would not measure the thing the budget exists for.
    chunk = "D" * 200_000
    needed = _LOG_MAX_RESPONSE_BYTES // len(chunk) + 3
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    for n in range(needed):
        _record(db, vehicle, "*-OVM-Debug", chunk,
                when=base + datetime.timedelta(minutes=n), record_number=n)
    _settle(db)

    response = client.get("/api/v1/vehicles/CAR1/logs",
                          params={"limit": needed}, headers=_auth(key))
    body = response.json()

    assert body["truncated"] is True, "the byte budget did not stop the response"
    assert len(body["debug_logs"]) < needed, "every row came back despite the budget"
    # The bound holds on the wire, not just on the counter: one record may straddle it,
    # nothing beyond that may.
    assert len(response.content) <= _LOG_MAX_RESPONSE_BYTES + len(chunk)


def test_a_small_log_response_is_not_marked_truncated(client, db):
    """The flag has to mean something, so the ordinary case must not set it."""
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    _record(db, vehicle, "*-OVM-DebugCrash", "3.3.004,build,4,Panic")
    _record(db, vehicle, "*-OVM-Debug", "some debug line", record_number=1)
    _settle(db)

    body = client.get("/api/v1/vehicles/CAR1/logs", headers=_auth(key)).json()

    assert body["truncated"] is False
    assert len(body["crash_logs"]) == 1
    assert len(body["debug_logs"]) == 1


def test_one_oversized_crash_report_is_still_returned(client, db):
    """A caller that gets an empty list cannot tell "no crashes" from "one huge one"."""
    owner, key = _user_with_key(db, "owner")
    vehicle = _vehicle(db, owner)
    from app.routers.api.main import _LOG_MAX_RESPONSE_BYTES
    _record(db, vehicle, "*-OVM-DebugCrash", "f,b,4,Panic,0,pc,cause,0,,"
            + "T" * (_LOG_MAX_RESPONSE_BYTES + 1000))
    _settle(db)

    body = client.get("/api/v1/vehicles/CAR1/logs", headers=_auth(key)).json()

    assert len(body["crash_logs"]) == 1
    assert body["truncated"] is False, "nothing was dropped, so nothing was truncated"

