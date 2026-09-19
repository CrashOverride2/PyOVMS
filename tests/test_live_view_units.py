"""
The live view follows the profile's unit preference for every value it formats.

`app/static/js/vehicle_live_view.js` is the one derivation behind the dashboard
card, the vehicle page's overview, its TPMS and cell-sensor tiles. Distance already
followed the preference; temperature was hard-wired to Celsius and tyre pressure to
bar, so a profile switched to imperial read "68 mi" beside "20.0 °C".

The file is plain browser JS with no module system, so it is run through node with
a `window` stub. Skipped where node is not installed (CI has no JS toolchain); the
file's syntax is still checked by the vehicle-page tests that render it.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LIVE_VIEW = REPO_ROOT / "app" / "static" / "js" / "vehicle_live_view.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

PAYLOAD = {
    "isV2Online": True, "isV3Online": False, "soc": 55, "units": "K",
    "estimated_range": 100, "lastMessageAt": None,
    "v2_metrics": {"environment.temp_ambient_c": 20, "environment.temp_battery_c": 30},
    "v3_metrics": {},
}


def _run(imperial: bool) -> dict:
    script = f"""
        const window = {{}};
        {LIVE_VIEW.read_text()}
        const view = window.ovmsLiveView.create({{ lang: 'en', imperial: {json.dumps(imperial)}, labels: {{}} }});
        const out = view.derive({json.dumps(PAYLOAD)});
        console.log(JSON.stringify({{
            ambient: out.ambientTempText, battery: out.batteryTempText, range: out.rangeText,
            t20: view.temperature(20), tNull: view.temperature(null),
            p25: view.pressure(2.5), pNull: view.pressure(null), imperial: view.imperial,
        }}));
    """
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_metric_profile_reads_celsius_and_bar():
    out = _run(imperial=False)
    assert out["ambient"] == "20.0 °C"
    assert out["battery"] == "30.0 °C"
    assert out["range"] == "100 km"
    assert out["t20"] == "20.0 °C"
    assert out["p25"] == "2.50 bar"
    assert out["imperial"] is False


def test_imperial_profile_reads_fahrenheit_and_psi():
    out = _run(imperial=True)
    assert out["ambient"] == "68.0 °F"
    assert out["battery"] == "86.0 °F"
    assert out["range"] == "62 mi"
    assert out["t20"] == "68.0 °F"
    assert out["p25"] == "36.3 psi"
    assert out["imperial"] is True


def test_a_missing_reading_is_null_not_a_unit():
    """The callers substitute their own placeholder ('T: N/A'); the view must not
    hand back '°F' with nothing in front of it."""
    out = _run(imperial=True)
    assert out["tNull"] is None
    assert out["pNull"] is None


# ---------------------------------------------------------------------------
# offline: the last known state of charge is shown, but not in colour
# ---------------------------------------------------------------------------

def _derive(payload: dict) -> dict:
    script = f"""
        const window = {{}};
        {LIVE_VIEW.read_text()}
        const view = window.ovmsLiveView.create({{ lang: 'en', imperial: false, labels: {{}} }});
        const out = view.derive({json.dumps(payload)});
        console.log(JSON.stringify({{ online: out.online, socText: out.socText, socClass: out.socClass,
                                     barClass: out.barClass, barWidth: out.barStyle.width, isCharging: out.isCharging }}));
    """
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_an_online_vehicle_shows_its_charge_in_colour():
    out = _derive({"isV2Online": False, "isV3Online": True, "soc": 80, "v3_metrics": {"v.c.charging": "yes"}})
    assert out["online"] is True
    assert out["socText"] == "80%"
    assert out["socClass"] == "text-green-400"
    assert out["barClass"] == "bg-gradient-to-r from-green-600 to-green-400 ovms-charging"
    assert out["barWidth"] == "80%"


def test_an_offline_vehicle_shows_its_last_charge_in_grey():
    """
    The value is the last one heard, not the battery now: a green 80 % on a module
    that went quiet a week ago read as current. The number and the bar go grey, the
    width stays (the level is still information), and the charging sweep — which says
    "happening now" — is off, even if the last frame said charging.
    """
    out = _derive({"isV2Online": False, "isV3Online": False, "soc": 80, "v3_metrics": {"v.c.charging": "yes"}})
    assert out["online"] is False
    assert out["socText"] == "80%"
    assert out["socClass"] == "text-text-secondary"
    assert out["barClass"] == "bg-gray-600"
    assert out["barWidth"] == "80%"
    assert out["isCharging"] is True, "the charge tiles still tell what the last frame said"


def test_an_unknown_charge_is_grey_and_empty_whether_online_or_not():
    for online in (True, False):
        out = _derive({"isV2Online": online, "isV3Online": False, "soc": None})
        assert out["socText"] == "–"
        assert out["socClass"] == "text-text-secondary"
        assert out["barClass"] == "bg-gray-600"
        assert out["barWidth"] == "0%"
