"""
The vehicle page's "Events" tab: climate and 12 V events of the parked vehicle.

What is pinned here:

* the tab exists only where events can be recorded — charge logging on and a V3
  protocol (`v3` or `both`); a V2-only vehicle carries none of the metrics;
* its labels are translated (the profile's locale, not English);
* the position button opens the page's own map (`addVehicleMapBaseLayer`, the
  Protomaps tiles of the overview), never a link to an external map;
* `mapEvent()` — the one place the API row becomes what the partial binds — hides
  every figure the vehicle did not report, converts temperatures through the
  profile's unit preference, keeps a recorded row undeletable and names the
  12 V charge a climate event ran. It is taken out of the rendered page and run
  under node, so the test sees the script the browser gets (skipped without node).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
REPO_ROOT = Path(__file__).resolve().parent.parent


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
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _make_user(db):
    user = models_db.User(
        username="alice", email="alice@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_vehicle(db, owner, *, protocol="v3", charge_logging=True, vehicle_id="EVTCAR"):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id, protocol=protocol,
                                enable_charge_logging=charge_logging, encrypted_server_password=b"x")
    db.add(vehicle)
    db.commit()
    return vehicle


def _login(client):
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    assert token is not None
    response = client.post(
        "/login",
        data={"username": "alice", "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _page(client, vehicle_id="EVTCAR", headers=None) -> str:
    response = client.get(f"/vehicle/{vehicle_id}", headers=headers)
    assert response.status_code == 200, response.text
    return response.text


def _has_events_tab(html: str) -> bool:
    return 'data-tab="events"' in html


@pytest.mark.parametrize("protocol", ["v3", "both"])
def test_tab_is_shown_for_a_v3_vehicle_with_charge_logging(client, db, protocol):
    _make_vehicle(db, _make_user(db), protocol=protocol)
    _login(client)
    html = _page(client)
    assert _has_events_tab(html)
    assert "eventLogState: createEventLogState()" in html


def test_no_tab_for_a_v2_only_vehicle(client, db):
    _make_vehicle(db, _make_user(db), protocol="v2")
    _login(client)
    assert not _has_events_tab(_page(client))


def test_no_tab_without_charge_logging(client, db):
    _make_vehicle(db, _make_user(db), charge_logging=False)
    _login(client)
    assert not _has_events_tab(_page(client))


def test_the_tab_label_follows_the_locale(client, db):
    _make_vehicle(db, _make_user(db))
    _login(client)
    html = _page(client, headers={"Accept-Language": "de"})
    assert "<span>Ereignisse</span>" in html
    assert "Klimatisierung" in html


# --- the derivation, run under node ---------------------------------------------------

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _main_script(html: str) -> str:
    scripts = re.findall(r"<script nonce=\"[^\"]+\">(.*?)</script>", html, re.S)
    page = [s for s in scripts if "function createEventLogState" in s]
    assert len(page) == 1
    return page[0]


def _extract(script: str, start: str, end: str) -> str:
    i = script.index(start)
    j = script.index(end, i)
    return script[i:j]


def _derive(html: str, rows: list, imperial: bool = False) -> list:
    script = _main_script(html)
    translations = _extract(script, "const vehicleDetailTranslations = {", "const initialLiveData")
    event_state = _extract(script, "const EVENT_KIND_CLASSES", "function bindTripPreviewImage")
    live_view = (REPO_ROOT / "app" / "static" / "js" / "vehicle_live_view.js").read_text()
    program = f"""
        const window = {{}};
        {live_view}
        const vehicleDetailConfig = {{ liveView: {{ lang: 'en', imperial: {json.dumps(imperial)} }} }};
        const liveView = window.ovmsLiveView.create({{ lang: 'en', imperial: {json.dumps(imperial)}, labels: {{}} }});
        {translations}
        {event_state}
        const state = createEventLogState();
        state.dateTimeFormatter = new Intl.DateTimeFormat('en', {{ timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short' }});
        console.log(JSON.stringify({json.dumps(rows)}.map((row) => state.mapEvent(row))));
    """
    result = subprocess.run(["node", "-e", program], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


CLIMATE = {
    "id": "11111111-1111-1111-1111-111111111111", "kind": "climate",
    "start_time": "2026-10-09T06:40:00Z", "end_time": "2026-10-09T07:00:00Z",
    "duration_seconds": 1200, "start_soc": 81.0, "end_soc": 79.5,
    "latitude": 49.44, "longitude": 7.77,
    "cabin_temp_start": 4.0, "cabin_temp_end": 21.0, "cabin_setpoint": 21.5, "ambient_temp": 2.0,
    "aux_charged": True, "aux_voltage_start": 12.31, "aux_voltage_end": 14.4, "aux_energy_wh": 35.0,
    "source": "both", "in_progress": False,
}
BOOST = {
    "id": "22222222-2222-2222-2222-222222222222", "kind": "aux_charge",
    "start_time": "2026-10-09T03:00:00Z", "end_time": None, "duration_seconds": None,
    "start_soc": None, "end_soc": None, "latitude": None, "longitude": None,
    "cabin_temp_start": None, "cabin_temp_end": None, "cabin_setpoint": None, "ambient_temp": None,
    "aux_charged": False, "aux_voltage_start": 12.1, "aux_voltage_end": None, "aux_energy_wh": None,
    "source": "metric", "in_progress": True,
}


@needs_node
def test_map_event_shows_what_was_reported_and_nothing_else(client, db):
    _make_vehicle(db, _make_user(db))
    _login(client)
    climate, boost = _derive(_page(client), [CLIMATE, BOOST])

    assert climate["isClimate"] and not climate["isAuxCharge"]
    assert climate["kindText"] == "Climate control"
    assert climate["showAuxChargedBadge"] is True
    assert climate["durationText"] == "20m"
    assert climate["socText"] == "81.0 % → 79.5 %"
    assert climate["cabinTempText"] == "4.0 °C → 21.0 °C"
    assert climate["setpointText"] == "21.5 °C"
    assert climate["auxVoltageText"] == "12.31 V → 14.40 V"
    assert climate["auxEnergyText"] == "35 Wh"
    # The position opens on the page's own map, not on an external site.
    assert climate["showLocation"] is True
    assert (climate["latitude"], climate["longitude"]) == (49.44, 7.77)
    assert "mapHref" not in climate
    assert climate["canDelete"] is True

    # A boost being recorded: no climate figures, no position, no delete.
    assert boost["isAuxCharge"] and boost["kindText"] == "12 V battery charge"
    assert boost["showAuxChargedBadge"] is False
    assert boost["inProgress"] is True and boost["canDelete"] is False
    assert boost["showSoc"] is False and boost["showCabinTemp"] is False
    assert boost["showSetpoint"] is False and boost["showAmbient"] is False
    assert boost["showAuxEnergy"] is False and boost["showLocation"] is False
    assert boost["auxVoltageText"] == "12.10 V"
    assert boost["durationText"] != "N/A"  # elapsed time while it runs


@needs_node
def test_map_event_follows_the_imperial_profile(client, db):
    _make_vehicle(db, _make_user(db))
    _login(client)
    (climate,) = _derive(_page(client), [CLIMATE], imperial=True)
    assert climate["setpointText"] == "70.7 °F"
    assert climate["ambientText"] == "35.6 °F"


@needs_node
def test_an_unknown_kind_reads_generically(client, db):
    _make_vehicle(db, _make_user(db))
    _login(client)
    (row,) = _derive(_page(client), [{**CLIMATE, "kind": "something_new", "aux_charged": False}])
    assert row["kindText"] == "Event"
    assert not row["isClimate"] and not row["isAuxCharge"]


@needs_node
def test_the_page_script_parses(client, db, tmp_path):
    """The tab's state lives in the page's one inline script; a syntax error there
    takes every tab of the page down with it, not only this one."""
    _make_vehicle(db, _make_user(db))
    _login(client)
    source = tmp_path / "vehicle_detail.js"
    source.write_text(_main_script(_page(client)))
    result = subprocess.run(["node", "--check", str(source)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_the_position_opens_the_pages_own_map(client, db):
    _make_vehicle(db, _make_user(db))
    _login(client)
    html = _page(client)
    assert 'id="event-position-map"' in html
    assert "openstreetmap.org/?mlat" not in html
    script = _main_script(html)
    draw = _extract(script, "drawMap(lat, lon", "closeMap() {")
    assert "addVehicleMapBaseLayer(this.map, container)" in draw


def test_our_stylesheet_and_live_view_carry_a_version(client, db):
    """A rebuilt main.css must reach a browser that cached the previous one: the
    static route sends no Cache-Control, and a stale copy lacks the classes a new
    template uses (the position dialog had no backdrop and a 0 px map)."""
    from app.routers.ui import asset_version

    _make_vehicle(db, _make_user(db))
    _login(client)
    html = _page(client)
    assert f"css/main.css?v={asset_version('css/main.css')}" in html
    assert f"js/vehicle_live_view.js?v={asset_version('js/vehicle_live_view.js')}" in html
    assert asset_version("css/main.css") != "0"
    assert asset_version("css/does-not-exist.css") == "0"
