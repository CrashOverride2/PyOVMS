from typing import Dict, Any, Optional, Tuple
from app.models import db as models_db 
from app.models.protocol import TPMSMessageDataY 
from .parsing_helpers import _safe_get_from_list, _safe_int_parse, safe_format_float_str, _safe_float_parse
from app.metrics_manager import metrics_manager
import logging
import re

logger = logging.getLogger(__name__)

# Based on common ESP-IDF exception causes
ESP32_REASON_CODE_MAP = {
    "1": "Illegal Instruction",
    "2": "Syscall",
    "3": "Instruction Fetch Error",
    "4": "Load/Store Prohibited",
    "5": "Integer Divide by Zero",
    "6": "Load/Store Alignment Error",
    "7": "Privileged Instruction",
    "8": "Alloca Exception",
    "9": "Load/Store Error",
    "12": "PID Not Found",
    "13": "Contention",
    "20": "Instruction Fetch Prohibited",
    "28": "Stack Overflow",
    "29": "Stack Overflow",
}

def _parse_v3_metrics_to_v2_style(v3_metrics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Converts a flat dictionary of V3 metrics into a nested structure similar to V2 parsed data."""
    if not v3_metrics:
        return {}

    status, location, tpms, diag = {}, {}, {}, {}

    v2_to_v3_map = {
        ('status', 'soc'): ['v.b.soc'],
        ('status', 'units'): ['v.b.unit', 'v.b.units'],
        ('status', 'estimated_range'): ['v.b.range.est'],
        ('status', 'charge_energy_consumed_kwh10'): ['v.c.kwh'],
        ('status', 'line_voltage'): ['v.c.voltage'],
        ('status', 'charge_current'): ['v.c.current'],
        ('status', 'charge_state_text'): ['v.c.state'],
        ('status', 'charge_mode_text'): ['v.c.mode'],
        ('status', 'battery_voltage'): ['v.b.voltage'],
        ('status', 'battery_current'): ['v.b.current'],
        ('status', 'battery_soh'): ['v.b.soh'],
        ('location', 'lat'): ['v.p.latitude'],
        ('location', 'lon'): ['v.p.longitude'],
        ('diag', 'vehicle_12v'): ['v.b.12v.voltage', 'v.c.12v.voltage'],
    }

    for (category, v2_key), v3_keys in v2_to_v3_map.items():
        for v3_key in v3_keys:
            if v3_key in v3_metrics:
                value = v3_metrics[v3_key]
                if category == 'status':
                    if v2_key in ('line_voltage', 'charge_current', 'battery_voltage', 'battery_current'):
                        status[v2_key] = safe_format_float_str(value, 1)
                    else:
                        status[v2_key] = value
                elif category == 'location':
                    location[v2_key] = value
                elif category == 'diag':
                    if v2_key == 'vehicle_12v':
                        diag[v2_key] = safe_format_float_str(value, 2)
                    else:
                        diag[v2_key] = value
                break 
    
    tpms_wheel_data: Dict[str, Dict[str, Any]] = {}
    tpms_regex = re.compile(r"^v\.t\.(?P<wheel>fl|fr|rl|rr)\.(?P<type>p|t|h|s)$")
    for key, value in v3_metrics.items():
        match = tpms_regex.match(key)
        if match:
            wheel_code = match.group('wheel').upper()
            metric_type = match.group('type')
            
            if wheel_code not in tpms_wheel_data:
                tpms_wheel_data[wheel_code] = {"name": wheel_code}

            if metric_type == 'p':
                pressure_kpa = _safe_float_parse(value)
                if pressure_kpa is not None:
                    tpms_wheel_data[wheel_code]['pressure_bar'] = round(pressure_kpa / 100, 2)
            elif metric_type == 't':
                tpms_wheel_data[wheel_code]['temperature_c'] = _safe_float_parse(value)
            elif metric_type == 'h':
                tpms_wheel_data[wheel_code]['health_pct'] = _safe_float_parse(value)

    WHEEL_ORDER = ["FR", "FL", "RR", "RL"]
    aggregated_topics = {
        'v.t.pressure': ('pressure_bar', lambda v: round(_safe_float_parse(v) / 100, 2) if _safe_float_parse(v) is not None else None),
        'v.t.temp': ('temperature_c', lambda v: _safe_float_parse(v)),
        'v.t.health': ('health_pct', lambda v: _safe_float_parse(v)),
        'v.t.alert': ('alert_level', lambda v: _safe_int_parse(v)),
    }

    for topic, (target_key, parser_func) in aggregated_topics.items():
        if topic in v3_metrics and isinstance(v3_metrics[topic], str):
            values = v3_metrics[topic].split(',')
            for i, wheel_code in enumerate(WHEEL_ORDER):
                if i < len(values):
                    if wheel_code not in tpms_wheel_data:
                        tpms_wheel_data[wheel_code] = {"name": wheel_code}
                    
                    parsed_value = parser_func(values[i])
                    if parsed_value is not None:
                        tpms_wheel_data[wheel_code][target_key] = parsed_value

    if tpms_wheel_data:
        sorted_wheels = sorted(tpms_wheel_data.values(), key=lambda x: ('FR', 'FL', 'RR', 'RL').index(x['name']) if x['name'] in ('FR', 'FL', 'RR', 'RL') else 99)
        tpms = {
            "type": "V3",
            "wheels": sorted_wheels,
            "validity": {"pressure": True, "temperature": True}
        }

    if status and 'units' not in status:
        status['units'] = 'K'

    return {
        "status_parsed": status if status else None,
        "location_parsed": location if location else None,
        "tpms_parsed": tpms if tpms else None,
        "diag_parsed": diag if diag else None,
    }


def parse_stored_msgs_for_vehicle_info(db_vehicle: Optional[models_db.Vehicle]) -> Tuple[Optional[Dict], Optional[Dict], Optional[Dict], Optional[Dict]]:
    """
    Parses stored raw messages from a Vehicle DB object and merges them with live V3 data.
    Returns (status_parsed, location_parsed, tpms_parsed, diag_parsed)
    """
    status_parsed, loc_parsed, tpms_parsed, diag_parsed = _parse_v2_messages(db_vehicle)
    v3_metrics = metrics_manager.get_metrics_for_vehicle(db_vehicle.vehicle_id) if db_vehicle else None

    if v3_metrics:
        v3_parsed = _parse_v3_metrics_to_v2_style(v3_metrics)
        if v3_parsed.get("status_parsed"):
            if status_parsed is None: status_parsed = {}
            status_parsed.update(v3_parsed["status_parsed"])
        if v3_parsed.get("location_parsed"):
            if loc_parsed is None: loc_parsed = {}
            loc_parsed.update(v3_parsed["location_parsed"])
        if v3_parsed.get("tpms_parsed"):
            tpms_parsed = v3_parsed["tpms_parsed"]
        if v3_parsed.get("diag_parsed"):
            if diag_parsed is None: diag_parsed = {}
            diag_parsed.update(v3_parsed["diag_parsed"])
    
    return status_parsed, loc_parsed, tpms_parsed, diag_parsed


def _parse_v2_messages(db_vehicle: Optional[models_db.Vehicle]) -> Tuple[Optional[Dict], Optional[Dict], Optional[Dict], Optional[Dict]]:
    """
    The original function to parse only the stored V2 messages.
    """
    status_parsed, loc_parsed, tpms_parsed, diag_parsed = None, None, None, None
    
    if db_vehicle:
        if db_vehicle.latest_status_msg:
            s_payload_parts = db_vehicle.latest_status_msg.split(',')[1:] 

            soc_val = _safe_get_from_list(s_payload_parts, 0, "N/A")
            units_val = _safe_get_from_list(s_payload_parts, 1, "N/A")
            
            raw_charge_state_code = _safe_get_from_list(s_payload_parts, 4, "N/A")
            raw_charge_mode_code = _safe_get_from_list(s_payload_parts, 5, "N/A")

            charge_state_map = {"0": "Standard", "1": "Topping Off", "4": "Done", "d": "Preparing", "s": "Charging", "t": "Heating",
                                "stopped": "Stopped", "charging": "Charging", "topoff": "Topoff", "done": "Done", 
                                "prepare": "Preparing", "heating": "Heating"}
            charge_mode_map = {"0": "Standard", "1": "Range", "2": "Performance", "s": "Storage",
                               "standard": "Standard", "storage": "Storage", "range": "Range", "performance": "Performance"}

            charge_state_text_val = charge_state_map.get(raw_charge_state_code.lower(), raw_charge_state_code.capitalize() if raw_charge_state_code != "N/A" else "N/A")
            charge_mode_text_val = charge_mode_map.get(raw_charge_mode_code.lower(), raw_charge_mode_code.capitalize() if raw_charge_mode_code != "N/A" else "N/A")
            
            status_parsed = {
                "soc": soc_val, "units": units_val,
                "charge_state": raw_charge_state_code, "charge_mode": raw_charge_mode_code,
                "charge_state_text": charge_state_text_val, "charge_mode_text": charge_mode_text_val,
                "battery_voltage": safe_format_float_str(_safe_get_from_list(s_payload_parts, 32, "N/A"), 1),
                "battery_current": safe_format_float_str(_safe_get_from_list(s_payload_parts, 36, "N/A"), 1),
                "line_voltage": safe_format_float_str(_safe_get_from_list(s_payload_parts, 2, "N/A"), 1),
                "charge_current": safe_format_float_str(_safe_get_from_list(s_payload_parts, 3, "N/A"), 1),
                "estimated_range": _safe_get_from_list(s_payload_parts, 7, "N/A"),
                "battery_soh": _safe_get_from_list(s_payload_parts, 33, "N/A"),
                "raw": db_vehicle.latest_status_msg[:80]+"..." if db_vehicle.latest_status_msg else "N/A"
            }

        if db_vehicle.latest_location_msg:
            l_payload_parts = db_vehicle.latest_location_msg.split(',')[1:]
            lat_str = _safe_get_from_list(l_payload_parts, 0, "N/A")
            lon_str = _safe_get_from_list(l_payload_parts, 1, "N/A")
            lat_val_parsed: Any = "N/A"; lon_val_parsed: Any = "N/A"
            # float() on protocol garbage is the only failure expected here; a bare
            # except also caught KeyboardInterrupt and CancelledError.
            try: lat_val_parsed = float(lat_str) if lat_str != "N/A" else "N/A"
            except (ValueError, TypeError): pass
            try: lon_val_parsed = float(lon_str) if lon_str != "N/A" else "N/A"
            except (ValueError, TypeError): pass
            loc_parsed = {
                "lat": lat_val_parsed, "lon": lon_val_parsed,
                "raw": db_vehicle.latest_location_msg[:60]+"..." if db_vehicle.latest_location_msg else "N/A"
            }
        
        if db_vehicle.latest_diag_msg:
            d_payload_parts = db_vehicle.latest_diag_msg.split(',')[1:]
            vehicle_12v_val = _safe_get_from_list(d_payload_parts, 14, "N/A")
            diag_parsed = {
                "vehicle_12v": safe_format_float_str(vehicle_12v_val, 2),
                "raw": db_vehicle.latest_diag_msg[:80]+"..." if db_vehicle.latest_diag_msg else "N/A"
            }

        if db_vehicle.latest_tpms_y_msg:
            try:
                y_payload_str = db_vehicle.latest_tpms_y_msg.split(',', 1)[1]
                y_data = TPMSMessageDataY.model_validate(y_payload_str)
                wheels_data = []
                for wheel_reading in y_data.wheel_readings:
                    pressure_bar = round(wheel_reading.pressure_kpa / 100, 2) if wheel_reading.pressure_kpa is not None else None
                    wheels_data.append({
                        "name": wheel_reading.name, "pressure_bar": pressure_bar,
                        "temperature_c": wheel_reading.temperature_c, "health_pct": wheel_reading.health_pct,
                        "alert_level": wheel_reading.alert_level,
                    })
                tpms_parsed = {
                    "type": "Y", "wheels": wheels_data,
                    "validity": {
                        "pressure": y_data.pressures_valid, "temperature": y_data.temperatures_valid,
                        "health": y_data.health_states_valid, "alert": y_data.alert_levels_valid,
                    },
                    "raw": db_vehicle.latest_tpms_y_msg[:120]+"..."
                }
            except Exception as e:
                logger.error(f"Error parsing Y TPMS for {db_vehicle.vehicle_id}: {e}. Raw: {db_vehicle.latest_tpms_y_msg}")
                tpms_parsed = {"type": "Y", "raw": db_vehicle.latest_tpms_y_msg[:120]+"...", "error": str(e), "wheels": []}
        elif db_vehicle.latest_tpms_w_msg: 
            w_payload_parts = db_vehicle.latest_tpms_w_msg.split(',')[1:]
            psi_to_bar = lambda psi_str: round(float(psi_str) * 0.0689476, 2) if psi_str and psi_str != "N/A" else None
            def safe_float_temp(temp_str):
                try: return float(temp_str)
                except (ValueError, TypeError): return None
            wheel_map_w = [
                {"name": "FR", "p_idx": 0, "t_idx": 1}, {"name": "RR", "p_idx": 2, "t_idx": 3},
                {"name": "FL", "p_idx": 4, "t_idx": 5}, {"name": "RL", "p_idx": 6, "t_idx": 7},
            ]
            wheels_data = []
            for wheel_info in wheel_map_w:
                wheels_data.append({
                    "name": wheel_info["name"],
                    "pressure_bar": psi_to_bar(_safe_get_from_list(w_payload_parts, wheel_info["p_idx"], None)),
                    "temperature_c": safe_float_temp(_safe_get_from_list(w_payload_parts, wheel_info["t_idx"], None)),
                })
            stale_indicator_w_str = _safe_get_from_list(w_payload_parts, 8, None)
            is_valid_w = bool(stale_indicator_w_str == "1") if stale_indicator_w_str is not None else None
            tpms_parsed = {
                "type": "W", "wheels": wheels_data,
                "validity": { "pressure": is_valid_w, "temperature": is_valid_w },
                "raw": db_vehicle.latest_tpms_w_msg[:120]+"..."
            }
    
    return status_parsed, loc_parsed, tpms_parsed, diag_parsed

def parse_crash_log_data(data_blob: str) -> Dict[str, Any]:
    """Parses a raw crash log data string into a structured dictionary."""
    parts = data_blob.split(',')
    parsed = {}
    try:
        part2 = _safe_get_from_list(parts, 2, "")
        part3 = _safe_get_from_list(parts, 3, "")

        reason_code = "Unknown"
        reason_text_from_log = "Unknown"

        if part2.isdigit():
            reason_code = part2
            reason_text_from_log = part3
        elif part3.isdigit():
            reason_code = part3
            reason_text_from_log = part2
        else: 
            reason_code = part2
            reason_text_from_log = part3

        final_reason_text = "Crash" 
        
        if reason_text_from_log and reason_text_from_log.strip() and reason_text_from_log != "Unknown":
             final_reason_text = reason_text_from_log.strip()
        elif reason_code and reason_code != "Unknown":
            mapped_text = ESP32_REASON_CODE_MAP.get(reason_code)
            if mapped_text:
                final_reason_text = mapped_text
        
        parsed = {
            'firmware': _safe_get_from_list(parts, 0, "Unknown"),
            'build_id': _safe_get_from_list(parts, 1, "Unknown"),
            'reason_code': reason_code,
            'reason_text': final_reason_text,
            'is_abort': bool(_safe_int_parse(_safe_get_from_list(parts, 4, "0"), 0)),
            'pc': _safe_get_from_list(parts, 5, "N/A"),
            'exc_cause': _safe_get_from_list(parts, 6, "N/A"),
            'is_our_abort': bool(_safe_int_parse(_safe_get_from_list(parts, 7, "0"), 0)),
            'abort_details': _safe_get_from_list(parts, 8, ""),
            'backtrace': _safe_get_from_list(parts, 9, "").strip(),
            'crash_task_prio': _safe_get_from_list(parts, 10, "N/A"),
            'crash_task_name': _safe_get_from_list(parts, 11, "N/A"),
            'running_task_prio': _safe_get_from_list(parts, 12, "N/A"),
            'running_task_name': _safe_get_from_list(parts, 13, "N/A"),
            'running_task_state': _safe_get_from_list(parts, 14, "N/A"),
            'last_event_prio': _safe_get_from_list(parts, 15, "N/A"),
            'last_event_sender': _safe_get_from_list(parts, 16, "N/A"),
            'last_event_prio_prev': _safe_get_from_list(parts, 17, "N/A"),
            'last_event_sender_prev': _safe_get_from_list(parts, 18, "N/A"),
            'running_task_runtime': _safe_get_from_list(parts, 19, "N/A"),
            'last_event_subscriber': _safe_get_from_list(parts, 20, "N/A"),
            'last_event_subscriber_prev': _safe_get_from_list(parts, 21, "N/A"),
            'raw': data_blob
        }
    except IndexError:
        logger.warning(f"Index error while parsing crash log data: {data_blob[:100]}...")
        parsed['error'] = "Incomplete log data"
        parsed['raw'] = data_blob

    return parsed