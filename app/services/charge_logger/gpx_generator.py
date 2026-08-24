from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ChargeLog


def generate_gpx_for_charge(charge: 'ChargeLog') -> str:
    """
    Generate a GPX file containing a waypoint for the charge session start location.

    Args:
        charge: ChargeLog object with start location data

    Returns:
        GPX XML content as a string
    """
    if charge.start_latitude is None or charge.start_longitude is None:
        raise ValueError("Charge log does not have start location data")

    # Create GPX root element
    gpx = ET.Element('gpx', {
        'version': '1.1',
        'creator': 'PyOVMS Charge Logger',
        'xmlns': 'http://www.topografix.com/GPX/1/1',
        'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'xsi:schemaLocation': 'http://www.topografix.com/GPX/1/1 http://www.topografix.com/GPX/1/1/gpx.xsd'
    })

    # Add metadata
    metadata = ET.SubElement(gpx, 'metadata')
    name = ET.SubElement(metadata, 'name')
    name.text = f'Charge Session {charge.id}'
    time = ET.SubElement(metadata, 'time')
    time.text = charge.start_time.strftime('%Y-%m-%dT%H:%M:%SZ') if charge.start_time else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Add waypoint for charge start location
    wpt = ET.SubElement(gpx, 'wpt', {
        'lat': str(charge.start_latitude),
        'lon': str(charge.start_longitude)
    })

    # Waypoint name
    wpt_name = ET.SubElement(wpt, 'name')
    wpt_name.text = 'Charge Start'

    # Waypoint description with charge details
    desc_parts = []
    if charge.start_time:
        desc_parts.append(f"Start: {charge.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if charge.end_time:
        desc_parts.append(f"End: {charge.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if charge.start_soc is not None:
        desc_parts.append(f"Start SOC: {charge.start_soc:.1f}%")
    if charge.end_soc is not None:
        desc_parts.append(f"End SOC: {charge.end_soc:.1f}%")
    if charge.energy_added_kwh is not None:
        desc_parts.append(f"Energy: {charge.energy_added_kwh:.2f} kWh")
    if charge.start_odometer is not None:
        desc_parts.append(f"Odometer: {charge.start_odometer:.1f} km")

    if desc_parts:
        desc = ET.SubElement(wpt, 'desc')
        desc.text = ', '.join(desc_parts)

    # Add timestamp
    wpt_time = ET.SubElement(wpt, 'time')
    wpt_time.text = charge.start_time.strftime('%Y-%m-%dT%H:%M:%SZ') if charge.start_time else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Convert to string with XML declaration
    ET.register_namespace('', 'http://www.topografix.com/GPX/1/1')
    tree = ET.ElementTree(gpx)

    import io
    output = io.BytesIO()
    tree.write(output, encoding='utf-8', xml_declaration=True)
    return output.getvalue().decode('utf-8')
