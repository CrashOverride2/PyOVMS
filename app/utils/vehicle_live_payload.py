"""The live-data payload of one vehicle, as the `vehicle:<id>` WebSocket topic carries it.

One builder for the two places that need the same shape: the 2-second broadcaster in
`lifespan.py`, and the dashboard's first render, which embeds this payload per card so
the page shows the same numbers before the first update as after it. The vehicle page
reads the same keys from its socket. Change a key here and every consumer follows.

Synchronous on purpose — it parses stored messages and reads two in-memory managers —
so a caller on the event loop runs it in a threadpool.
"""

import datetime
from typing import Any, Dict

from app.connection_manager import manager as connection_manager
from app.metrics_manager import metrics_manager
from app.models import db as models_db
from app.utils.timestamps import as_utc_iso
from app.utils.vehicle_data_presenter import parse_stored_msgs_for_vehicle_info
from app.utils.vehicle_state_parser import parse_v2_messages_to_metrics_dict

# A V3 module that has not published for this long is shown as offline. The same
# window connection_manager applies when it builds a VehicleInfo.
V3_ONLINE_WINDOW_SECONDS = 15 * 60


def is_v3_online(vehicle_db: models_db.Vehicle, now_utc: datetime.datetime) -> bool:
    last_seen = vehicle_db.last_seen_v3
    if not last_seen:
        return False
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=datetime.timezone.utc)
    return (now_utc - last_seen).total_seconds() < V3_ONLINE_WINDOW_SECONDS


def build_vehicle_live_payload(vehicle_db: models_db.Vehicle) -> Dict[str, Any]:
    status_parsed, loc_parsed, tpms_parsed, diag_parsed = parse_stored_msgs_for_vehicle_info(vehicle_db)
    v2_metrics = parse_v2_messages_to_metrics_dict(vehicle_db)
    v3_metrics = metrics_manager.get_metrics_for_vehicle(vehicle_db.vehicle_id)
    status = status_parsed or {}

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    return {
        "isV2Online": vehicle_db.vehicle_id in connection_manager.car_connections,
        "isV3Online": is_v3_online(vehicle_db, now_utc),
        "soc": status.get('soc'),
        "units": status.get('units'),
        "line_voltage": status.get('line_voltage'),
        "charge_current": status.get('charge_current'),
        "charge_state_text": status.get('charge_state_text'),
        "charge_mode_text": status.get('charge_mode_text'),
        "estimated_range": status.get('estimated_range'),
        "battery_voltage": status.get('battery_voltage'),
        "battery_current": status.get('battery_current'),
        "battery_soh": status.get('battery_soh'),
        "vehicle_12v": diag_parsed.get('vehicle_12v') if diag_parsed else None,
        "lat": loc_parsed.get('lat') if loc_parsed else None,
        "lon": loc_parsed.get('lon') if loc_parsed else None,
        "lastMessageAt": as_utc_iso(vehicle_db.last_message_at),
        "tpms_data": tpms_parsed,
        "v2_metrics": v2_metrics,
        "v3_metrics": v3_metrics,
    }
