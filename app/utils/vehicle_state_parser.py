from typing import Dict, Any
from app.models.db import Vehicle
from app.models.protocol import StatusMessageData, LocationMessageData, EnvironmentMessageData
import logging

from app.metrics_manager import metrics_manager
from app.utils.parsing_helpers import (
    _safe_float_parse,
    _safe_int_parse,
    _safe_truncated_int_str,
)

logger = logging.getLogger(__name__)

def parse_vehicle_state_to_json(vehicle_db: Vehicle) -> Dict[str, Any]:
    """
    Parses the stored raw messages from the vehicle DB object and merges with live V3 metrics
    into a comprehensive JSON state, similar to the original OVMS web UI's vehicle.php output.
    This uses the Pydantic models for more robust parsing for V2 and direct mapping for V3.
    """
    state: Dict[str, Any] = {}

    target_keys_numeric_float = [
        "altitude", "batt_capacity", "batt_current", "batt_range_speed", "battvoltage",
        "cac100", "charge_limit_range", "chargecurrent", "chargekwh", "chargelimit",
        "chargerefficiency", "chargepower", "chargepowerinput", "direction", "energyrecd",
        "energyused", "estimatedrange", "idealrange", "idealrange_max", "invefficiency",
        "invpower", "latitude", "longitude", "power", "soh", "speed",
        "temperature_ambient", "temperature_battery", "temperature_cabin", "temperature_charger",
        "temperature_motor", "temperature_pem", "vehicle12v", "vehicle12v_current", "vehicle12v_ref"
    ]
    target_keys_numeric_int = [
        "alarmsounding", "bt_open", "carawake", "carlocked", "caron", "charge_etr_full",
        "charge_etr_limit", "charge_etr_range", "charge_etr_soc", "charge_limit_soc",
        "chargeduration", "charge_estimate", "charging", "charging_12v", "chargetimermode",
        "cp_dooropen", "fl_dooropen", "fr_dooropen", "gpslock", "handbrake", "odometer",
        "parkingtimer", "pilotpresent", "tr_open", "tripmeter", "valetmode"
    ]
    target_keys_string = [
        "chargestate", "chargesubstate", "chargestarttime", "chargetimerstale", "chargetype",
        "drivemode", "m_msgtime", "mode", "units"
    ]

    for key in target_keys_numeric_float: state[key] = "0.0"
    for key in target_keys_numeric_int: state[key] = 0
    for key in target_keys_string: state[key] = "N/A"

    state["m_msgtime"] = vehicle_db.last_message_at.strftime('%Y-%m-%d %H:%M:%S') if vehicle_db.last_message_at else "N/A"

    if vehicle_db.latest_status_msg:
        try:
            s_payload_str = vehicle_db.latest_status_msg.split(',', 1)[1]
            s_data = StatusMessageData.model_validate(s_payload_str)
            
            state["soc"] = str(s_data.soc) if s_data.soc is not None else "0.0"
            state["units"] = s_data.units or "K"
            state["linevoltage"] = f"{s_data.line_voltage:.1f}" if s_data.line_voltage is not None else "0.0"
            state["chargecurrent"] = f"{s_data.charge_current:.2f}" if s_data.charge_current is not None else "0.00"
            state["chargestate"] = s_data.charge_state.lower() if s_data.charge_state else "stopped"
            state["mode"] = s_data.charge_mode.lower() if s_data.charge_mode else "standard"
            state["idealrange"] = str(int(s_data.ideal_range)) if s_data.ideal_range is not None else "0"
            state["estimatedrange"] = str(int(s_data.estimated_range)) if s_data.estimated_range is not None else "0"
            state["chargelimit"] = f"{s_data.charge_limit_amps:.1f}" if s_data.charge_limit_amps is not None else "0.0"
            state["chargeduration"] = str(s_data.charge_duration_minutes) if s_data.charge_duration_minutes is not None else "0"
            state["chargekwh"] = f"{s_data.charge_energy_consumed_kwh10:.1f}" if s_data.charge_energy_consumed_kwh10 is not None else "0.0"
            state["chargesubstate"] = s_data.charge_sub_state or "0"
            state["chargetimermode"] = s_data.charge_timer_mode if s_data.charge_timer_mode is not None else 0
            state["chargestarttime"] = s_data.charge_timer_start_time or "0"
            state["chargetimerstale"] = s_data.charge_timer_stale or "0"
            state["cac100"] = f"{s_data.vehicle_cac100_ah:.2f}" if s_data.vehicle_cac100_ah is not None else "0.00"
            state["charge_etr_full"] = str(s_data.acc_mins_to_full) if s_data.acc_mins_to_full is not None else "0"
            state["charge_etr_limit"] = str(s_data.acc_mins_to_limit) if s_data.acc_mins_to_limit is not None else "0"
            state["charge_limit_range"] = str(int(s_data.acc_range_limit)) if s_data.acc_range_limit is not None else "0"
            state["charge_limit_soc"] = str(s_data.acc_soc_limit) if s_data.acc_soc_limit is not None else "0"
            state["charge_estimate"] = str(s_data.acc_charge_time_estimate_current_charger_mins) if s_data.acc_charge_time_estimate_current_charger_mins is not None else "0"
            state["charge_etr_range"] = str(s_data.charge_etr_range_limit_mins) if s_data.charge_etr_range_limit_mins is not None else "0"
            state["charge_etr_soc"] = str(s_data.charge_etr_soc_limit_mins) if s_data.charge_etr_soc_limit_mins is not None else "0"
            state["idealrange_max"] = str(int(s_data.max_ideal_range)) if s_data.max_ideal_range is not None else "0"
            state["chargetype"] = s_data.charge_plug_type_id or "0"
            state["chargepower"] = f"{s_data.charge_power_output_kw:.2f}" if s_data.charge_power_output_kw is not None else "0.00"
            state["battvoltage"] = f"{s_data.battery_voltage:.2f}" if s_data.battery_voltage is not None else "0.00"
            state["soh"] = f"{s_data.battery_soh_percent:.1f}" if s_data.battery_soh_percent is not None else "0.0"
            state["chargepowerinput"] = f"{s_data.charge_power_input_kw:.2f}" if s_data.charge_power_input_kw is not None else "0.00"
            state["chargerefficiency"] = f"{s_data.charger_efficiency_percent:.2f}" if s_data.charger_efficiency_percent is not None else "0.00"
            state["batt_current"] = f"{s_data.battery_current:.2f}" if s_data.battery_current is not None else "0.00"
            state["batt_range_speed"] = f"{s_data.battery_ideal_range_speed:.1f}" if s_data.battery_ideal_range_speed is not None else "0.0"
            state["charge_kwh_grid"] = f"{s_data.energy_drawn_grid_running_session_kwh:.1f}" if s_data.energy_drawn_grid_running_session_kwh is not None else "0.0"
            state["batt_capacity"] = f"{s_data.main_battery_usable_capacity_kwh:.1f}" if s_data.main_battery_usable_capacity_kwh is not None else "0.0"
        except Exception as e:
            logger.error(f"Error parsing S message for {vehicle_db.vehicle_id} into Pydantic model: {e}. Data: {vehicle_db.latest_status_msg}")

    if vehicle_db.latest_location_msg:
        try:
            l_payload_str = vehicle_db.latest_location_msg.split(',', 1)[1]
            l_data = LocationMessageData.model_validate(l_payload_str)
            state["latitude"] = f"{l_data.latitude:.6f}" if l_data.latitude is not None else "0.000000"
            state["longitude"] = f"{l_data.longitude:.6f}" if l_data.longitude is not None else "0.000000"
            state["direction"] = f"{l_data.direction:.1f}" if l_data.direction is not None else "0.0"
            state["altitude"] = f"{l_data.altitude:.1f}" if l_data.altitude is not None else "0.0"
            state["gpslock"] = l_data.gps_lock if l_data.gps_lock is not None else 0
            state["speed"] = str(int(l_data.speed)) if l_data.speed is not None else "0"
            state["tripmeter"] = str(l_data.trip_meter_10th_unit // 10) if l_data.trip_meter_10th_unit is not None else "0"
            state["drivemode"] = l_data.drive_mode or "0"
            state["power"] = f"{l_data.battery_power_kw:.3f}" if l_data.battery_power_kw is not None else "0.000"
            state["energyused"] = f"{l_data.energy_used_wh:.3f}" if l_data.energy_used_wh is not None else "0.000"
            state["energyrecd"] = f"{l_data.energy_recovered_wh:.3f}" if l_data.energy_recovered_wh is not None else "0.000"
            state["invpower"] = f"{l_data.inverter_motor_power_kw:.3f}" if l_data.inverter_motor_power_kw is not None else "0.000"
            state["invefficiency"] = str(l_data.inverter_efficiency_percent) if l_data.inverter_efficiency_percent is not None else "0"
        except Exception as e:
            logger.error(f"Error parsing L message for {vehicle_db.vehicle_id} into Pydantic model: {e}. Data: {vehicle_db.latest_location_msg}")

    if vehicle_db.latest_diag_msg:
        try:
            d_payload_str = vehicle_db.latest_diag_msg.split(',', 1)[1]
            d_data = EnvironmentMessageData.model_validate(d_payload_str)
            state["fl_dooropen"] = 1 if d_data.left_door_open else 0
            state["fr_dooropen"] = 1 if d_data.right_door_open else 0
            state["cp_dooropen"] = 1 if d_data.charge_port_open else 0
            state["pilotpresent"] = 1 if d_data.pilot_present else 0
            state["charging"] = 1 if d_data.charging else 0
            state["handbrake"] = 1 if d_data.hand_brake_applied else 0
            state["caron"] = 1 if d_data.car_on else 0
            state["carlocked"] = 1 if d_data.car_locked else 0
            state["valetmode"] = 1 if d_data.valet_mode_active else 0
            state["bt_open"] = 1 if d_data.bonnet_open else 0
            state["tr_open"] = 1 if d_data.trunk_open else 0
            state["temperature_pem"] = f"{d_data.temp_pem_c:.1f}" if d_data.temp_pem_c is not None else "0.0"
            state["temperature_motor"] = f"{d_data.temp_motor_c:.1f}" if d_data.temp_motor_c is not None else "0.0"
            state["temperature_battery"] = f"{d_data.temp_battery_c:.1f}" if d_data.temp_battery_c is not None else "0.0"
            state["odometer"] = str(d_data.odometer_10th_unit // 10) if d_data.odometer_10th_unit is not None else "0"
            state["parkingtimer"] = str(d_data.parking_timer_seconds) if d_data.parking_timer_seconds is not None else "0"
            state["temperature_ambient"] = f"{d_data.temp_ambient_c:.1f}" if d_data.temp_ambient_c is not None else "0.0"
            state["carawake"] = 1 if d_data.car_awake else 0
            state["vehicle12v"] = f"{d_data.vehicle_12v_line_voltage:.2f}" if d_data.vehicle_12v_line_voltage is not None else "0.00"
            state["alarmsounding"] = 1 if d_data.alarm_sounding else 0
            state["vehicle12v_ref"] = f"{d_data.reference_voltage_12v:.2f}" if d_data.reference_voltage_12v is not None else "0.00"
            state["charging_12v"] = 1 if d_data.battery_12v_charging else 0
            state["temperature_charger"] = f"{d_data.temp_charger_c:.1f}" if d_data.temp_charger_c is not None else "0.0"
            state["vehicle12v_current"] = f"{d_data.vehicle_12v_current:.1f}" if d_data.vehicle_12v_current is not None else "0.0"
            state["temperature_cabin"] = f"{d_data.temp_cabin_c:.1f}" if d_data.temp_cabin_c is not None else "0.0"
        except Exception as e:
            logger.error(f"Error parsing D message for {vehicle_db.vehicle_id} into Pydantic model: {e}. Data: {vehicle_db.latest_diag_msg}")

    # Merge V3 Metrics
    v3_metrics = metrics_manager.get_metrics_for_vehicle(vehicle_db.vehicle_id)
    if v3_metrics:
        logger.debug(f"Merging V3 metrics for {vehicle_db.vehicle_id} into V2 state object.")
        
        v3_to_v2_map = {
            'v.b.soc': ('soc', _safe_float_parse, '%.1f'),
            'v.b.unit': ('units', str, None),
            'v.b.units': ('units', str, None),
            'v.c.voltage': ('linevoltage', _safe_float_parse, '%.1f'),
            'v.c.current': ('chargecurrent', _safe_float_parse, '%.2f'),
            'v.c.state': ('chargestate', lambda v: str(v).lower(), None),
            'v.c.mode': ('mode', lambda v: str(v).lower(), None),
            'v.b.range.est': ('estimatedrange', _safe_float_parse, '%.0f'),
            'v.b.range.ideal': ('idealrange', _safe_float_parse, '%.0f'),
            'v.c.kwh': ('chargekwh', _safe_float_parse, '%.1f'),
            'v.c.limit.amps': ('chargelimit', _safe_float_parse, '%.1f'),
            'v.c.duration.soc': ('charge_etr_soc', _safe_int_parse, None),
            'v.c.duration.range': ('charge_etr_range', _safe_int_parse, None),
            'v.c.duration.full': ('charge_etr_full', _safe_int_parse, None),
            'v.c.limit.soc': ('charge_limit_soc', _safe_int_parse, None),
            'v.c.limit.range': ('charge_limit_range', _safe_float_parse, '%.0f'),
            'v.b.voltage': ('battvoltage', _safe_float_parse, '%.2f'),
            'v.b.current': ('batt_current', _safe_float_parse, '%.2f'),
            'v.b.soh': ('soh', _safe_float_parse, '%.1f'),
            'v.p.latitude': ('latitude', _safe_float_parse, '%.6f'),
            'v.p.longitude': ('longitude', _safe_float_parse, '%.6f'),
            'v.p.direction': ('direction', _safe_float_parse, '%.1f'),
            'v.p.altitude': ('altitude', _safe_float_parse, '%.1f'),
            'v.p.gps.lock': ('gpslock', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.p.speed': ('speed', _safe_float_parse, '%.0f'),
            'v.p.trip': ('tripmeter', _safe_truncated_int_str, None),
            'v.p.odometer': ('odometer', _safe_truncated_int_str, None),
            'v.b.power': ('power', _safe_float_parse, '%.3f'),
            'v.b.energy.used': ('energyused', _safe_float_parse, '%.3f'),
            'v.b.energy.recd': ('energyrecd', _safe_float_parse, '%.3f'),
            'v.e.temp': ('temperature_ambient', _safe_float_parse, '%.1f'),
            'v.b.temp': ('temperature_battery', _safe_float_parse, '%.1f'),
            'v.m.temp': ('temperature_motor', _safe_float_parse, '%.1f'),
            'v.i.temp': ('temperature_pem', _safe_float_parse, '%.1f'),
            'v.c.temp': ('temperature_charger', _safe_float_parse, '%.1f'),
            'v.e.cabin.temp': ('temperature_cabin', _safe_float_parse, '%.1f'),
            'v.d.fl': ('fl_dooropen', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.d.fr': ('fr_dooropen', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.d.cp': ('cp_dooropen', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.c.pilot': ('pilotpresent', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.c.charging': ('charging', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.e.handbrake': ('handbrake', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.e.on': ('caron', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.e.locked': ('carlocked', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.e.valet': ('valetmode', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.d.bonnet': ('bt_open', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.d.trunk': ('tr_open', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.e.awake': ('carawake', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.e.alarm': ('alarmsounding', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
            'v.c.12v.charging': ('charging_12v', lambda v: 1 if str(v).lower() in ['true', '1'] else 0, None),
        }
        
        v12_sources = ['v.b.12v.voltage', 'v.c.12v.voltage', 'v.e.12v.voltage']
        for v3_key in v12_sources:
            if v3_key in v3_metrics:
                val = _safe_float_parse(v3_metrics.get(v3_key))
                if val is not None:
                    state['vehicle12v'] = f"{val:.2f}"
                    break

        # Per-metric try/except, unlike the V2 blocks above which wrap a whole message.
        #
        # Every value here comes off the wire from the vehicle. The V2 paths were
        # already guarded; this loop was not, so one unconvertible metric raised out
        # of the whole function and turned GET /vehicle_state into a 500 until the
        # metric expired — which the publisher could simply refresh. Isolating each
        # entry means a bad metric costs that one field, not the endpoint.
        for v3_key, (v2_key, converter, fmt) in v3_to_v2_map.items():
            if v3_key in v3_metrics:
                raw_val = v3_metrics[v3_key]
                try:
                    converted_val = converter(raw_val)
                    if converted_val is not None:
                        if fmt and isinstance(converted_val, (int, float)):
                            state[v2_key] = fmt % converted_val
                        else:
                            state[v2_key] = str(converted_val)
                except Exception as e:
                    logger.warning(
                        f"Dropping unconvertible V3 metric '{v3_key}' for "
                        f"{vehicle_db.vehicle_id}: {e!r} (raw: {str(raw_val)[:40]!r})"
                    )

    for key, value in list(state.items()): 
        if isinstance(value, bool):
            state[key] = 1 if value else 0
        elif value is None: 
            if key in target_keys_numeric_float: state[key] = "0.0"
            elif key in target_keys_numeric_int: state[key] = 0
            else: state[key] = "N/A"
        elif not isinstance(value, (str, int, float)): 
            state[key] = str(value)
       
        elif isinstance(value, float):
            if key in ["latitude", "longitude"]: state[key] = f"{value:.6f}"
            elif key in ["power", "energyused", "energyrecd", "invpower"]: state[key] = f"{value:.3f}"
            elif key in ["battvoltage", "cac100", "chargepowerinput", "chargerefficiency", "batt_current", "vehicle12v", "vehicle12v_ref", "chargepower"]: state[key] = f"{value:.2f}"
            elif key in ["linevoltage", "chargecurrent", "chargelimit", "idealrange", "estimatedrange", "soh", "batt_range_speed", "batt_capacity", "temperature_ambient", "temperature_battery", "temperature_cabin", "temperature_charger", "temperature_motor", "temperature_pem", "altitude", "direction", "chargekwh"]: state[key] = f"{value:.1f}"
            else: state[key] = str(value) 

    return state

def parse_v2_messages_to_metrics_dict(vehicle_db: Vehicle) -> Dict[str, Any]:
    """
    Parses stored raw V2 messages into a flat key-value dictionary for UI display.
    """
    metrics: Dict[str, Any] = {}
    
    def add_metrics_from_model(model_instance, prefix: str):
        for field, value in model_instance.model_dump().items():
            if field != 'raw_payload' and value is not None:
                metrics[f"{prefix}.{field}"] = value
    
    if vehicle_db.latest_status_msg:
        try:
            payload = vehicle_db.latest_status_msg.split(',', 1)[1]
            add_metrics_from_model(StatusMessageData.model_validate(payload), "status")
        except Exception as e:
            logger.warning(f"Failed to parse V2 Status message for metrics display: {e}")

    if vehicle_db.latest_location_msg:
        try:
            payload = vehicle_db.latest_location_msg.split(',', 1)[1]
            add_metrics_from_model(LocationMessageData.model_validate(payload), "location")
        except Exception as e:
            logger.warning(f"Failed to parse V2 Location message for metrics display: {e}")

    if vehicle_db.latest_diag_msg:
        try:
            payload = vehicle_db.latest_diag_msg.split(',', 1)[1]
            add_metrics_from_model(EnvironmentMessageData.model_validate(payload), "environment")
        except Exception as e:
            logger.warning(f"Failed to parse V2 Environment/Diag message for metrics display: {e}")
            
    return metrics