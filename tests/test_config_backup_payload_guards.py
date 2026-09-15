"""
What a configuration backup may contain, enforced at the API.

The document is stored as plain text on the strength of two guards: it names no
credential (every object key is checked, never a value) and it carries no image.
Both are refused with 422 rather than stored, and both are checked here against
the real route so the guard cannot quietly become a docstring.

The size limit is the cheapest check and runs first; the schema version is stored
even when it is newer than anything this server knows, so an old server never
blocks a new app; and another user's snapshot is not found, administrators
included.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.config import settings
from app.crud.apikey import KeyPurpose
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.routers.api.config_backups import MAX_DOCUMENT_DEPTH, MAX_SCHEMA_VERSION, document_depth
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


def _user_with_key(db, username="alice", *, admin=False, key_name=None, purpose=KeyPurpose.USER):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=admin, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _, plain_key = crud.apikey.create_api_key(
        db, user.id, key_name or f"{username}-key", purpose=purpose)
    return user, plain_key


def _post(client, key, document, **fields):
    body = {"kind": "manual", "payload": json.dumps(document) if not isinstance(document, str) else document}
    body.update(fields)
    return client.post(URL, json=body, headers={"X-API-Key": key})


GOOD = {"schemaVersion": 1, "settings": {"app_settings_theme": "matrix"},
        "vehicles": [{"id": "CAR1", "friendlyName": "Zoe"}]}


# --- size, shape ------------------------------------------------------------------

def test_an_oversized_payload_is_refused_before_anything_else(client, db):
    _, key = _user_with_key(db)
    padding = "x" * (settings.CONFIG_BACKUP_MAX_PAYLOAD_CHARS + 1)
    # Not even JSON: max_length must answer first, or the parser would.
    assert _post(client, key, padding).status_code == 422
    assert db.query(models_db.ConfigBackup).count() == 0


@pytest.mark.parametrize("payload", ["not json", "[1, 2]", '"a string"'])
def test_a_payload_that_is_not_a_json_object_is_refused(client, db, payload):
    _, key = _user_with_key(db)
    assert _post(client, key, payload).status_code == 422


@pytest.mark.parametrize("version", [None, "1", 0, True, 1.5])
def test_schema_version_must_be_a_positive_integer(client, db, version):
    _, key = _user_with_key(db)
    document = dict(GOOD)
    if version is None:
        document.pop("schemaVersion")
    else:
        document["schemaVersion"] = version
    assert _post(client, key, document).status_code == 422


def test_a_newer_schema_version_is_stored_not_refused(client, db):
    """An old server must not block a new app."""
    user, key = _user_with_key(db)
    response = _post(client, key, {**GOOD, "schemaVersion": 99})
    assert response.status_code == 201
    assert response.json()["schema_version"] == 99


@pytest.mark.parametrize("depth", [MAX_DOCUMENT_DEPTH + 1, 900, 5000])
def test_a_deeply_nested_payload_is_refused_not_crashed(client, db, depth):
    """A few hundred brackets used to be a RecursionError — in the key walk at
    about 450 levels, in the parser itself further out — and a RecursionError is
    a 500 with a hundred kilobytes of traceback in the log, per request."""
    _, key = _user_with_key(db)
    nested = "[" * depth + "]" * depth
    document = '{"schemaVersion": 1, "settings": {"x": ' + nested + '}, "vehicles": [], "commands": {}}'
    assert len(document) < settings.CONFIG_BACKUP_MAX_PAYLOAD_CHARS
    response = _post(client, key, document)
    assert response.status_code == 422
    assert "nested" in response.json()["detail"]
    assert db.query(models_db.ConfigBackup).count() == 0


def test_a_document_as_deep_as_a_real_one_is_stored(client, db):
    """vehicles[i].customLayoutConfig.dataPoints[j].<field> is the deepest path
    the app writes; the limit has to leave it room."""
    _, key = _user_with_key(db)
    document = {**GOOD, "vehicles": [{"id": "CAR1", "customLayoutConfig": {
        "dataPoints": [{"position": {"x": 0.5, "y": 0.5}, "metric": "v/b/soc"}]}}]}
    assert document_depth(document) < MAX_DOCUMENT_DEPTH // 2
    assert _post(client, key, document).status_code == 201


def test_document_depth_counts_containers_not_scalars():
    assert document_depth({}) == 1
    assert document_depth({"a": 1}) == 1
    assert document_depth({"a": {"b": 1}}) == 2
    assert document_depth({"a": [[{"b": []}]]}) == 5
    assert document_depth("scalar") == 0


# --- text the server cannot encode --------------------------------------------------
#
# JSON allows the escape \ud800, half of a surrogate pair, and Python's parser turns
# it into a str that UTF-8 refuses. Every one of these was a 500 with a traceback in
# the log, from an authenticated client: the content digest encodes, the database
# driver encodes, and the 422 that quotes a denied key encodes.

def _post_raw(client, key, raw: str):
    """The body as bytes, so an escape at the outer level reaches the server as
    written rather than being re-encoded by the test client."""
    return client.post(URL, content=raw.encode("utf-8"),
                       headers={"X-API-Key": key, "Content-Type": "application/json"})


INNER = r'{\"schemaVersion\":1,\"settings\":{\"x\":\"ok\"}}' 


@pytest.mark.parametrize("raw", [
    # escape at the outer level: the payload *text* itself carries the surrogate
    r'{"kind":"manual","payload":"{\"schemaVersion\":1,\"x\":\"\ud800\"}"}',
    # escape at the outer level in a body field that goes straight to a column
    r'{"kind":"manual","label":"\ud800","payload":"' + INNER + '"}',
    r'{"kind":"manual","device_name":"\ud800","payload":"' + INNER + '"}',
], ids=["payload-text", "label", "device_name"])
def test_a_surrogate_in_the_body_is_refused_not_crashed(client, db, raw):
    """pydantic refuses the str itself (string_unicode) — and then the 422 that
    reports it used to echo the offending input and fail to encode, a 500 from
    any endpoint with a string field in its body. The handler no longer echoes."""
    _, key = _user_with_key(db)
    response = _post_raw(client, key, raw)
    assert response.status_code == 422, response.text
    (error,) = response.json()["detail"]
    assert error["type"] == "string_unicode"
    assert "input" not in error, "the client's own bytes must not come back"
    assert db.query(models_db.ConfigBackup).count() == 0


@pytest.mark.parametrize("payload", [
    # the escape inside the payload text: seven clean ASCII bytes until json.loads
    '{"schemaVersion":1,"settings":{"x":"\\ud800"}}',
    # in a key, where the denied-key 422 would have quoted it
    '{"schemaVersion":1,"settings":{"\\ud800":1}}',
    # in a meta field that is copied into a column
    '{"schemaVersion":1,"meta":{"deviceName":"\\ud800"}}',
    # in a denied key: the 422 that names the key must itself be encodable
    '{"schemaVersion":1,"meta":{"password\\ud800":1}}',
], ids=["value", "key", "meta-column", "denied-key"])
def test_a_surrogate_escape_inside_the_payload_is_refused_not_crashed(client, db, payload):
    _, key = _user_with_key(db)
    assert payload.encode("utf-8"), "the text itself is clean; only the parsed document is not"
    response = _post(client, key, payload)
    assert response.status_code == 422, response.text
    assert "surrogate" in response.json()["detail"]
    assert db.query(models_db.ConfigBackup).count() == 0


def test_a_real_surrogate_pair_is_ordinary_text(client, db):
    """An emoji escaped the JSON way is a pair, not a lone half, and is stored."""
    _, key = _user_with_key(db)
    payload = '{"schemaVersion":1,"settings":{"theme":"\\ud83d\\ude00 matrix"}}'
    assert _post(client, key, payload).status_code == 201


# --- schemaVersion --------------------------------------------------------------------

@pytest.mark.parametrize("version", [MAX_SCHEMA_VERSION + 1, 2**63, 99999999999999999999999])
def test_a_schema_version_past_the_column_is_refused_not_crashed(client, db, version):
    """An Integer column holds 32 bits on PostgreSQL and MySQL; SQLite raised an
    OverflowError at insert time. Either way it was a 500."""
    _, key = _user_with_key(db)
    response = _post(client, key, {**GOOD, "schemaVersion": version})
    assert response.status_code == 422
    assert "schemaVersion" in response.json()["detail"]


def test_the_largest_schema_version_is_stored(client, db):
    _, key = _user_with_key(db)
    response = _post(client, key, {**GOOD, "schemaVersion": MAX_SCHEMA_VERSION})
    assert response.status_code == 201
    assert response.json()["schema_version"] == MAX_SCHEMA_VERSION


# --- meta.deviceId ----------------------------------------------------------------------

def test_an_overlong_meta_device_id_is_refused_not_silently_shortened(client, db):
    """Cut to 32 characters it would have named a different bucket; the body's
    own device_id is refused at 33, so meta is held to the same rule."""
    _, key = _user_with_key(db)
    document = {**GOOD, "meta": {"deviceId": "a" * 40}}
    response = _post(client, key, document)
    assert response.status_code == 422
    assert "deviceId" in response.json()["detail"]
    assert db.query(models_db.ConfigBackup).count() == 0


# --- credentials ------------------------------------------------------------------

@pytest.mark.parametrize("document", [
    {**GOOD, "vehicles": [{"id": "CAR1", "wifiApPassword": "hunter2"}]},
    {**GOOD, "settings": {"mqtt_password": "hunter2"}},
    {**GOOD, "commands": {"custom": [{"name": "x", "apiKey": "k"}]}},
    {**GOOD, "settings": {"shortcut_deeplink_token": "t"}},
    {**GOOD, "nested": {"deep": [{"module_secret": 1}]}},
])
def test_a_credential_shaped_key_anywhere_is_refused(client, db, document):
    _, key = _user_with_key(db)
    response = _post(client, key, document)
    assert response.status_code == 422
    assert db.query(models_db.ConfigBackup).count() == 0


def test_the_word_password_as_a_value_is_not_a_leak(client, db):
    """A command named "unlock password" is a name; only keys are scanned."""
    _, key = _user_with_key(db)
    document = {**GOOD, "commands": {"custom": [{"name": "password", "commandString": "secret token"}]}}
    assert _post(client, key, document).status_code == 201


# --- images -----------------------------------------------------------------------

@pytest.mark.parametrize("document", [
    {**GOOD, "assets": {"a1": {"file": "images/a1.png"}}},
    {**GOOD, "vehicles": [{"id": "CAR1", "customTopImagePath": "asset:a1"}]},
])
def test_a_payload_carrying_images_is_a_broken_client(client, db, document):
    _, key = _user_with_key(db)
    assert _post(client, key, document).status_code == 422


# --- request fields ---------------------------------------------------------------

@pytest.mark.parametrize("kind", ["", "backup", "AUTO", "manual "])
def test_kind_outside_auto_and_manual_is_refused(client, db, kind):
    _, key = _user_with_key(db)
    assert _post(client, key, GOOD, kind=kind).status_code == 422


@pytest.mark.parametrize("device_id", ["XYZ", "g" * 4, "a" * 33, "abc\n"])
def test_device_id_must_be_short_lowercase_hex(client, db, device_id):
    _, key = _user_with_key(db)
    assert _post(client, key, GOOD, device_id=device_id).status_code == 422


def test_a_payload_without_a_device_id_is_accepted(client, db):
    _, key = _user_with_key(db)
    response = _post(client, key, GOOD)
    assert response.status_code == 201
    assert response.json()["device_id"] is None


def test_the_device_id_and_name_may_come_from_the_document_meta(client, db):
    _, key = _user_with_key(db)
    document = {**GOOD, "meta": {"deviceId": "0123abcd", "deviceName": "Pixel 8",
                                 "appVersion": "2.3.0", "platform": "android"}}
    response = _post(client, key, document)
    assert response.status_code == 201
    body = response.json()
    assert body["device_id"] == "0123abcd"
    assert body["device_name"] == "Pixel 8"
    assert body["app_version"] == "2.3.0"
    assert body["platform"] == "android"


@pytest.mark.parametrize("field", ["label", "deviceName"])
def test_a_meta_text_with_a_line_break_is_refused_like_the_body_fields(client, db, field):
    """Both end up in a listing and in a download file name; the body fields refuse
    line breaks, and the fallback through meta must not be the way around that."""
    _, key = _user_with_key(db)
    document = {**GOOD, "meta": {field: "evil\r\nX-Injected: 1"}}
    assert _post(client, key, document).status_code == 422
    assert db.query(models_db.ConfigBackup).count() == 0


def test_a_missing_device_name_is_filled_from_the_device_key(client, db):
    """Device provisioning names keys `device-<name>`; that name labels the list."""
    _, key = _user_with_key(db, key_name="device-Carsten's Phone", purpose=KeyPurpose.DEVICE)
    response = _post(client, key, GOOD)
    assert response.status_code == 201
    assert response.json()["device_name"] == "Carsten's Phone"


# --- ownership --------------------------------------------------------------------

def test_the_stored_document_comes_back_byte_for_byte(client, db):
    _, key = _user_with_key(db)
    text = json.dumps(GOOD, indent=2, ensure_ascii=False) + "\n"
    backup_id = _post(client, key, text).json()["id"]

    response = client.get(f"{URL}/{backup_id}", headers={"X-API-Key": key})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.text == text


@pytest.mark.parametrize("method", ["get", "patch", "delete"])
def test_another_users_snapshot_is_not_found_even_for_an_admin(client, db, method):
    _, alice_key = _user_with_key(db, "alice")
    _, root_key = _user_with_key(db, "root", admin=True)
    backup_id = _post(client, alice_key, GOOD).json()["id"]

    response = client.request(
        method, f"{URL}/{backup_id}", headers={"X-API-Key": root_key},
        json={"kind": "manual"} if method == "patch" else None,
    )
    assert response.status_code == 404
    assert db.query(models_db.ConfigBackup).count() == 1


# --- quota and kill switch --------------------------------------------------------

def test_exceeding_the_storage_quota_stores_nothing(client, db, monkeypatch):
    _, key = _user_with_key(db)
    first = _post(client, key, GOOD)
    assert first.status_code == 201
    stored = first.json()["stored_chars"]

    monkeypatch.setattr(settings, "CONFIG_BACKUP_MAX_TOTAL_CHARS_PER_USER", stored + 10)
    response = _post(client, key, {**GOOD, "settings": {"x": "y" * 200}})

    assert response.status_code == 413
    assert db.query(models_db.ConfigBackup).count() == 1


def test_the_quota_endpoint_reports_both_counters(client, db):
    _, key = _user_with_key(db)
    _post(client, key, GOOD, kind="manual", device_id="aaaa")
    _post(client, key, {**GOOD, "x": 1}, kind="auto", device_id="aaaa")

    response = client.get(f"{URL}/quota", headers={"X-API-Key": key})
    assert response.status_code == 200
    body = response.json()
    assert body["manual_used"] == 1 and body["manual_max"] == settings.CONFIG_BACKUP_MAX_MANUAL
    assert body["auto_used"] == 1 and body["auto_max"] == settings.CONFIG_BACKUP_MAX_AUTO
    assert body["stored_chars"] > 0
    assert body["max_stored_chars"] == settings.CONFIG_BACKUP_MAX_TOTAL_CHARS_PER_USER

    scoped = client.get(f"{URL}/quota", params={"device_id": "bbbb"}, headers={"X-API-Key": key})
    assert scoped.json()["auto_used"] == 0


def test_the_kill_switch_keeps_the_routes_and_disables_the_feature(client, db, monkeypatch):
    _, key = _user_with_key(db)
    stored = _post(client, key, GOOD).json()["id"]
    monkeypatch.setattr(settings, "CONFIG_BACKUP_ENABLED", False)

    listing = client.get(URL, headers={"X-API-Key": key})
    assert listing.status_code == 200
    assert listing.json() == {"enabled": False, "items": []}

    assert _post(client, key, GOOD).status_code == 403
    assert client.get(f"{URL}/{stored}", headers={"X-API-Key": key}).status_code == 403
    assert client.patch(f"{URL}/{stored}", json={"kind": "manual"}, headers={"X-API-Key": key}).status_code == 403


def test_the_kill_switch_never_strands_data(client, db, monkeypatch):
    """Off means no new snapshots and nothing handed to the app — not that what
    is stored becomes impossible to remove."""
    _, key = _user_with_key(db)
    stored = _post(client, key, GOOD).json()["id"]
    monkeypatch.setattr(settings, "CONFIG_BACKUP_ENABLED", False)

    assert client.delete(f"{URL}/{stored}", headers={"X-API-Key": key}).status_code == 204
    assert db.query(models_db.ConfigBackup).count() == 0


def test_the_listing_needs_a_key(client):
    assert client.get(URL).status_code == 401
