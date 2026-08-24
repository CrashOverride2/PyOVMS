"""
GPX and KML export of a charge session.

Neither generator had a test. They are pure functions over a ChargeLog — no database, no
request — so there was no reason for that beyond nobody having written one, and export
bugs are the kind a user reports weeks later with a file you cannot reproduce.

Both are asserted by parsing the output back with ElementTree rather than by matching
substrings: a generator that emits almost-XML passes a substring check and fails in the
tool the user actually opens it with.

Nearly every field is optional in the model, and each one is guarded by its own `if` in
the generators — a partial session (still charging, no GPS lock at the end) is the normal
case, not the edge case, so those branches are covered here too.
"""

import datetime
import uuid
from xml.etree import ElementTree as ET

import pytest

from app.services.charge_logger.gpx_generator import generate_gpx_for_charge
from app.services.charge_logger.kml_generator import generate_kml_for_charge

GPX_NS = {"gpx": "http://www.topografix.com/GPX/1/1"}
KML_NS = {"kml": "http://www.opengis.net/kml/2.2"}


class FakeChargeLog:
    """Stand-in for the ORM object. The generators only read attributes, so binding a real
    session would add a database to a test that does not need one."""

    def __init__(self, **overrides):
        self.id = uuid.UUID("12345678-1234-5678-1234-567812345678")
        self.start_time = datetime.datetime(2026, 1, 1, 10, 0, tzinfo=datetime.timezone.utc)
        self.end_time = datetime.datetime(2026, 1, 1, 12, 30, tzinfo=datetime.timezone.utc)
        self.start_latitude = 49.4875
        self.start_longitude = 8.4660
        self.start_soc = 20.0
        self.end_soc = 80.0
        self.energy_added_kwh = 30.5
        self.max_power_kw = 11.0
        self.average_power_kw = 9.2
        self.start_odometer = 12345.6
        for key, value in overrides.items():
            setattr(self, key, value)


@pytest.fixture
def charge():
    return FakeChargeLog()


class TestGpx:
    def test_output_is_well_formed_xml(self, charge):
        ET.fromstring(generate_gpx_for_charge(charge))

    def test_root_declares_the_gpx_namespace_and_version(self, charge):
        root = ET.fromstring(generate_gpx_for_charge(charge))
        assert root.tag == "{http://www.topografix.com/GPX/1/1}gpx"
        assert root.get("version") == "1.1"

    def test_waypoint_carries_the_start_coordinates(self, charge):
        root = ET.fromstring(generate_gpx_for_charge(charge))
        wpt = root.find("gpx:wpt", GPX_NS)

        assert wpt is not None, "no waypoint in the GPX — the file marks nothing"
        assert float(wpt.get("lat")) == pytest.approx(charge.start_latitude)
        assert float(wpt.get("lon")) == pytest.approx(charge.start_longitude)

    def test_missing_position_is_refused_rather_than_exported_as_zero(self, charge):
        """0/0 is a real place in the Atlantic. Silently exporting it would put every
        position-less session on the same spot in the user's map."""
        charge.start_latitude = None
        with pytest.raises(ValueError):
            generate_gpx_for_charge(charge)

        charge.start_latitude = 49.4875
        charge.start_longitude = None
        with pytest.raises(ValueError):
            generate_gpx_for_charge(charge)

    def test_a_session_still_in_progress_exports(self, charge):
        """No end_time, no end_soc, no energy total — what an ongoing charge looks like."""
        charge.end_time = None
        charge.end_soc = None
        charge.energy_added_kwh = None
        charge.max_power_kw = None
        charge.average_power_kw = None
        charge.start_odometer = None

        ET.fromstring(generate_gpx_for_charge(charge))

    def test_missing_start_time_falls_back_to_now(self, charge):
        """The fallback path uses datetime.now(timezone.utc); it used to be the deprecated
        utcnow(). Asserted for shape, not value."""
        charge.start_time = None
        root = ET.fromstring(generate_gpx_for_charge(charge))
        time_el = root.find("gpx:metadata/gpx:time", GPX_NS)

        assert time_el is not None and time_el.text.endswith("Z")


class TestKml:
    def test_output_is_well_formed_xml(self, charge):
        ET.fromstring(generate_kml_for_charge(charge))

    def test_placemark_carries_the_start_coordinates(self, charge):
        root = ET.fromstring(generate_kml_for_charge(charge))
        coords = root.find(".//kml:Placemark/kml:Point/kml:coordinates", KML_NS)

        assert coords is not None, "no Point in the Placemark"
        lon, lat = coords.text.strip().split(",")[:2]
        assert float(lat) == pytest.approx(charge.start_latitude)
        assert float(lon) == pytest.approx(charge.start_longitude), (
            "KML orders coordinates longitude,latitude — the reverse of GPX. Swapping "
            "them puts a charge in Karlsruhe somewhere in Somalia."
        )

    def test_description_has_no_visible_cdata_markers(self, charge):
        """
        The regression this test was written for. The description was assembled with a
        literal '<![CDATA[' prefix and ']]>' suffix and then assigned to element.text —
        which ElementTree escapes, so the file contained '&lt;![CDATA[' and the markers
        showed up as text at the top and bottom of the balloon in every viewer.
        """
        root = ET.fromstring(generate_kml_for_charge(charge))
        description = root.find(".//kml:Placemark/kml:description", KML_NS)

        assert description is not None
        assert "CDATA" not in description.text, (
            "CDATA delimiters are being escaped into the description and will be shown "
            "to the user as literal text."
        )
        assert "]]>" not in description.text

    def test_description_carries_the_session_figures(self, charge):
        root = ET.fromstring(generate_kml_for_charge(charge))
        text = root.find(".//kml:Placemark/kml:description", KML_NS).text

        assert "20.0%" in text and "80.0%" in text, "start/end SOC missing"
        assert "+60.0%" in text, "SOC gained not computed"
        assert "30.50 kWh" in text, "energy added missing"
        assert "2h 30m" in text, "duration not computed from start/end time"

    def test_missing_position_is_refused(self, charge):
        charge.start_latitude = None
        with pytest.raises(ValueError):
            generate_kml_for_charge(charge)

    def test_a_session_still_in_progress_exports(self, charge):
        charge.end_time = None
        charge.end_soc = None
        charge.energy_added_kwh = None
        charge.max_power_kw = None
        charge.average_power_kw = None
        charge.start_odometer = None

        root = ET.fromstring(generate_kml_for_charge(charge))
        text = root.find(".//kml:Placemark/kml:description", KML_NS).text
        assert "Duration" not in text, "duration shown for a session with no end time"
        assert "SOC Gained" not in text

    def test_zero_values_are_not_dropped_as_falsy(self, charge):
        """0.0 kWh added and a 0% start SOC are real readings. The generators guard with
        `is not None`; a truthiness check would omit both rows."""
        charge.start_soc = 0.0
        charge.energy_added_kwh = 0.0

        text = ET.fromstring(generate_kml_for_charge(charge)).find(
            ".//kml:Placemark/kml:description", KML_NS
        ).text

        assert "0.0%" in text
        assert "0.00 kWh" in text
