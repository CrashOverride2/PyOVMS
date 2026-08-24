from xml.etree import ElementTree as ET
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ChargeLog


def generate_kml_for_charge(charge: 'ChargeLog') -> str:
    """
    Generate a KML file containing a placemark for the charge session start location.

    Args:
        charge: ChargeLog object with start location data

    Returns:
        KML XML content as a string
    """
    if charge.start_latitude is None or charge.start_longitude is None:
        raise ValueError("Charge log does not have start location data")

    # Create KML root element
    kml = ET.Element('kml', {
        'xmlns': 'http://www.opengis.net/kml/2.2'
    })

    # Document element
    doc = ET.SubElement(kml, 'Document')

    # Document name
    doc_name = ET.SubElement(doc, 'name')
    doc_name.text = f'Charge Session {charge.id}'

    # Style for charging icon
    style = ET.SubElement(doc, 'Style', {'id': 'chargeIcon'})
    icon_style = ET.SubElement(style, 'IconStyle')
    icon = ET.SubElement(icon_style, 'Icon')
    href = ET.SubElement(icon, 'href')
    href.text = 'http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png'
    color = ET.SubElement(icon_style, 'color')
    color.text = 'ff00ff00'  # Green color in AABBGGRR format

    # Placemark for charge location
    placemark = ET.SubElement(doc, 'Placemark')

    # Placemark name
    pm_name = ET.SubElement(placemark, 'name')
    pm_name.text = 'Charge Start'

    # Style reference
    style_url = ET.SubElement(placemark, 'styleUrl')
    style_url.text = '#chargeIcon'

    # Description with charge details.
    #
    # No CDATA wrapper. It used to open with '<![CDATA[' and close with ']]>', but this is
    # assigned to description.text, and ElementTree escapes whatever it is given — so the
    # delimiters were written out as '&lt;![CDATA[' and ']]&gt;' and appeared as literal
    # text at the top and bottom of the balloon in every KML viewer.
    #
    # The escaping is not the problem: entity-escaped HTML in a <description> is the
    # documented alternative to CDATA, and viewers unescape and render it. Only the
    # delimiters were wrong.
    desc_parts = []
    desc_parts.append('<h3>Charge Session Details</h3>')
    desc_parts.append('<table border="1" cellpadding="5">')

    if charge.start_time:
        desc_parts.append(f'<tr><td><b>Start Time</b></td><td>{charge.start_time.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>')
    if charge.end_time:
        desc_parts.append(f'<tr><td><b>End Time</b></td><td>{charge.end_time.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>')

    if charge.start_time and charge.end_time:
        duration = charge.end_time - charge.start_time
        hours = int(duration.total_seconds() // 3600)
        minutes = int((duration.total_seconds() % 3600) // 60)
        desc_parts.append(f'<tr><td><b>Duration</b></td><td>{hours}h {minutes}m</td></tr>')

    if charge.start_soc is not None:
        desc_parts.append(f'<tr><td><b>Start SOC</b></td><td>{charge.start_soc:.1f}%</td></tr>')
    if charge.end_soc is not None:
        desc_parts.append(f'<tr><td><b>End SOC</b></td><td>{charge.end_soc:.1f}%</td></tr>')
    if charge.start_soc is not None and charge.end_soc is not None:
        soc_gained = charge.end_soc - charge.start_soc
        desc_parts.append(f'<tr><td><b>SOC Gained</b></td><td>+{soc_gained:.1f}%</td></tr>')

    if charge.energy_added_kwh is not None:
        desc_parts.append(f'<tr><td><b>Energy Charged</b></td><td>{charge.energy_added_kwh:.2f} kWh</td></tr>')
    if charge.max_power_kw is not None:
        desc_parts.append(f'<tr><td><b>Max Power</b></td><td>{charge.max_power_kw:.2f} kW</td></tr>')
    if charge.average_power_kw is not None:
        desc_parts.append(f'<tr><td><b>Avg Power</b></td><td>{charge.average_power_kw:.2f} kW</td></tr>')
    if charge.start_odometer is not None:
        desc_parts.append(f'<tr><td><b>Odometer</b></td><td>{charge.start_odometer:.1f} km</td></tr>')

    desc_parts.append('</table>')

    description = ET.SubElement(placemark, 'description')
    description.text = ''.join(desc_parts)

    # Timestamp
    if charge.start_time:
        timestamp = ET.SubElement(placemark, 'TimeStamp')
        when = ET.SubElement(timestamp, 'when')
        when.text = charge.start_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Point coordinates (longitude, latitude, altitude)
    point = ET.SubElement(placemark, 'Point')
    coordinates = ET.SubElement(point, 'coordinates')
    coordinates.text = f'{charge.start_longitude},{charge.start_latitude},0'

    # Convert to string with XML declaration
    tree = ET.ElementTree(kml)

    import io
    output = io.BytesIO()
    tree.write(output, encoding='utf-8', xml_declaration=True)
    return output.getvalue().decode('utf-8')
