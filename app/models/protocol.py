from pydantic import BaseModel, model_validator, ValidationError
from typing import Optional, List, Any, Dict
import logging
from app.utils.parsing_helpers import _parse_payload_to_dict, _safe_float_parse, _safe_int_parse

logger = logging.getLogger(__name__)

class ProtocolDataBase(BaseModel):
    raw_payload: str # Store the original string payload

class StatusMessageData(ProtocolDataBase):
    soc: Optional[float] = None
    units: Optional[str] = None
    line_voltage: Optional[float] = None
    charge_current: Optional[float] = None
    charge_state: Optional[str] = None
    charge_mode: Optional[str] = None
    ideal_range: Optional[float] = None
    estimated_range: Optional[float] = None
    charge_limit_amps: Optional[float] = None
    charge_duration_minutes: Optional[int] = None
    charger_b4_byte: Optional[str] = None # Index 10
    charge_energy_consumed_kwh10: Optional[float] = None # Index 11 (1/10 kWh)
    charge_sub_state: Optional[str] = None # Index 12
    charge_state_numeric: Optional[str] = None # Index 13
    charge_mode_numeric: Optional[str] = None # Index 14
    charge_timer_mode: Optional[int] = None # Index 15 (0=onplugin, 1=timer)
    charge_timer_start_time: Optional[str] = None # Index 16
    charge_timer_stale: Optional[str] = None # Index 17 (-1=none, 0=stale, >0 ok)
    vehicle_cac100_ah: Optional[float] = None # Index 18
    acc_mins_to_full: Optional[int] = None # Index 19
    acc_mins_to_limit: Optional[int] = None # Index 20
    acc_range_limit: Optional[float] = None # Index 21
    acc_soc_limit: Optional[int] = None # Index 22
    cooldown_active: Optional[int] = None # Index 23 (0=no, 1=yes)
    cooldown_batt_temp_lower_limit: Optional[float] = None # Index 24
    cooldown_time_limit_minutes: Optional[int] = None # Index 25
    acc_charge_time_estimate_current_charger_mins: Optional[int] = None # Index 26
    charge_etr_range_limit_mins: Optional[int] = None # Index 27
    charge_etr_soc_limit_mins: Optional[int] = None # Index 28
    max_ideal_range: Optional[float] = None # Index 29
    charge_plug_type_id: Optional[str] = None # Index 30
    charge_power_output_kw: Optional[float] = None # Index 31
    battery_voltage: Optional[float] = None # Index 32
    battery_soh_percent: Optional[float] = None # Index 33
    charge_power_input_kw: Optional[float] = None # Index 34
    charger_efficiency_percent: Optional[float] = None # Index 35
    battery_current: Optional[float] = None # Index 36
    battery_ideal_range_speed: Optional[float] = None # Index 37 (mph/kph)
    energy_sum_running_charge_kwh: Optional[float] = None # Index 38
    energy_drawn_grid_running_session_kwh: Optional[float] = None # Index 39
    main_battery_usable_capacity_kwh: Optional[float] = None # Index 40
    last_charge_end_datetime_seconds_epoch: Optional[int] = None # Index 41

    @model_validator(mode='before')
    @classmethod
    def parse_s_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("StatusMessageData expects a string payload")
        
        payload_dict = _parse_payload_to_dict(data)
        parsed = {"raw_payload": data}

        parsed['soc'] = _safe_float_parse(payload_dict.get(0))
        parsed['units'] = payload_dict.get(1)
        parsed['line_voltage'] = _safe_float_parse(payload_dict.get(2))
        parsed['charge_current'] = _safe_float_parse(payload_dict.get(3))
        parsed['charge_state'] = payload_dict.get(4)
        parsed['charge_mode'] = payload_dict.get(5)
        parsed['ideal_range'] = _safe_float_parse(payload_dict.get(6))
        parsed['estimated_range'] = _safe_float_parse(payload_dict.get(7))
        parsed['charge_limit_amps'] = _safe_float_parse(payload_dict.get(8))
        parsed['charge_duration_minutes'] = _safe_int_parse(payload_dict.get(9))
        parsed['charger_b4_byte'] = payload_dict.get(10)
        parsed['charge_energy_consumed_kwh10'] = _safe_float_parse(payload_dict.get(11))
        parsed['charge_sub_state'] = payload_dict.get(12)
        parsed['charge_state_numeric'] = payload_dict.get(13)
        parsed['charge_mode_numeric'] = payload_dict.get(14)
        parsed['charge_timer_mode'] = _safe_int_parse(payload_dict.get(15))
        parsed['charge_timer_start_time'] = payload_dict.get(16)
        parsed['charge_timer_stale'] = payload_dict.get(17)
        parsed['vehicle_cac100_ah'] = _safe_float_parse(payload_dict.get(18))
        parsed['acc_mins_to_full'] = _safe_int_parse(payload_dict.get(19))
        parsed['acc_mins_to_limit'] = _safe_int_parse(payload_dict.get(20))
        parsed['acc_range_limit'] = _safe_float_parse(payload_dict.get(21))
        parsed['acc_soc_limit'] = _safe_int_parse(payload_dict.get(22))
        parsed['cooldown_active'] = _safe_int_parse(payload_dict.get(23))
        parsed['cooldown_batt_temp_lower_limit'] = _safe_float_parse(payload_dict.get(24))
        parsed['cooldown_time_limit_minutes'] = _safe_int_parse(payload_dict.get(25))
        parsed['acc_charge_time_estimate_current_charger_mins'] = _safe_int_parse(payload_dict.get(26))
        parsed['charge_etr_range_limit_mins'] = _safe_int_parse(payload_dict.get(27))
        parsed['charge_etr_soc_limit_mins'] = _safe_int_parse(payload_dict.get(28))
        parsed['max_ideal_range'] = _safe_float_parse(payload_dict.get(29))
        parsed['charge_plug_type_id'] = payload_dict.get(30)
        parsed['charge_power_output_kw'] = _safe_float_parse(payload_dict.get(31))
        parsed['battery_voltage'] = _safe_float_parse(payload_dict.get(32))
        parsed['battery_soh_percent'] = _safe_float_parse(payload_dict.get(33))
        parsed['charge_power_input_kw'] = _safe_float_parse(payload_dict.get(34))
        parsed['charger_efficiency_percent'] = _safe_float_parse(payload_dict.get(35))
        parsed['battery_current'] = _safe_float_parse(payload_dict.get(36))
        parsed['battery_ideal_range_speed'] = _safe_float_parse(payload_dict.get(37))
        parsed['energy_sum_running_charge_kwh'] = _safe_float_parse(payload_dict.get(38))
        parsed['energy_drawn_grid_running_session_kwh'] = _safe_float_parse(payload_dict.get(39))
        parsed['main_battery_usable_capacity_kwh'] = _safe_float_parse(payload_dict.get(40))
        parsed['last_charge_end_datetime_seconds_epoch'] = _safe_int_parse(payload_dict.get(41))
        return parsed

class LocationMessageData(ProtocolDataBase):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    direction: Optional[float] = None
    altitude: Optional[float] = None
    gps_lock: Optional[int] = None # 0=nogps, 1=goodgps
    stale_gps_indicator: Optional[str] = None # -1=none, 0=stale, >0 ok
    speed: Optional[float] = None # in distance units per hour
    trip_meter_10th_unit: Optional[int] = None
    drive_mode: Optional[str] = None # car specific
    battery_power_kw: Optional[float] = None # negative = charging
    energy_used_wh: Optional[float] = None
    energy_recovered_wh: Optional[float] = None
    inverter_motor_power_kw: Optional[float] = None # positive = output
    inverter_efficiency_percent: Optional[int] = None
    gps_mode_indicator: Optional[str] = None
    gps_satellite_count: Optional[int] = None
    gps_hdop: Optional[float] = None
    gps_speed: Optional[float] = None
    gps_signal_quality_percent: Optional[int] = None

    @model_validator(mode='before')
    @classmethod
    def parse_l_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("LocationMessageData expects a string payload")

        payload_dict = _parse_payload_to_dict(data)
        parsed = {"raw_payload": data}
        
        parsed['latitude'] = _safe_float_parse(payload_dict.get(0))
        parsed['longitude'] = _safe_float_parse(payload_dict.get(1))
        parsed['direction'] = _safe_float_parse(payload_dict.get(2))
        parsed['altitude'] = _safe_float_parse(payload_dict.get(3))
        parsed['gps_lock'] = _safe_int_parse(payload_dict.get(4))
        parsed['stale_gps_indicator'] = payload_dict.get(5)
        parsed['speed'] = _safe_float_parse(payload_dict.get(6))
        parsed['trip_meter_10th_unit'] = _safe_int_parse(payload_dict.get(7))
        parsed['drive_mode'] = payload_dict.get(8)
        parsed['battery_power_kw'] = _safe_float_parse(payload_dict.get(9))
        parsed['energy_used_wh'] = _safe_float_parse(payload_dict.get(10))
        parsed['energy_recovered_wh'] = _safe_float_parse(payload_dict.get(11))
        parsed['inverter_motor_power_kw'] = _safe_float_parse(payload_dict.get(12))
        parsed['inverter_efficiency_percent'] = _safe_int_parse(payload_dict.get(13))
        parsed['gps_mode_indicator'] = payload_dict.get(14)
        parsed['gps_satellite_count'] = _safe_int_parse(payload_dict.get(15))
        parsed['gps_hdop'] = _safe_float_parse(payload_dict.get(16))
        parsed['gps_speed'] = _safe_float_parse(payload_dict.get(17))
        parsed['gps_signal_quality_percent'] = _safe_int_parse(payload_dict.get(18))
        return parsed

class EnvironmentMessageData(ProtocolDataBase):
    left_door_open: Optional[bool] = None
    right_door_open: Optional[bool] = None
    charge_port_open: Optional[bool] = None
    pilot_present: Optional[bool] = None
    charging: Optional[bool] = None
    hand_brake_applied: Optional[bool] = None
    car_on: Optional[bool] = None 
    car_locked: Optional[bool] = None
    valet_mode_active: Optional[bool] = None
    bonnet_open: Optional[bool] = None
    trunk_open: Optional[bool] = None
    lock_unlock_state: Optional[str] = None 
    temp_pem_c: Optional[float] = None 
    temp_motor_c: Optional[float] = None 
    temp_battery_c: Optional[float] = None 
    trip_meter_10th_unit: Optional[int] = None 
    odometer_10th_unit: Optional[int] = None 
    speed_dph: Optional[float] = None  
    parking_timer_seconds: Optional[int] = None 
    temp_ambient_c: Optional[float] = None 
    car_awake: Optional[bool] = None
    cooling_pump_on: Optional[bool] = None
    motor_controller_logged_in: Optional[bool] = None
    motor_controller_config_mode: Optional[bool] = None
    stale_temps_pem_motor_batt_indicator: Optional[str] = None 
    stale_ambient_temp_indicator: Optional[str] = None 
    vehicle_12v_line_voltage: Optional[float] = None 
    alarm_sounding: Optional[bool] = None
    reference_voltage_12v: Optional[float] = None 
    rear_left_door_open: Optional[bool] = None
    rear_right_door_open: Optional[bool] = None
    frunk_open: Optional[bool] = None
    battery_12v_charging: Optional[bool] = None
    aux_12v_systems_online: Optional[bool] = None
    hvac_running: Optional[bool] = None
    temp_charger_c: Optional[float] = None 
    vehicle_12v_current: Optional[float] = None 
    temp_cabin_c: Optional[float] = None 

    @model_validator(mode='before')
    @classmethod
    def parse_d_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("EnvironmentMessageData expects a string payload")

        p = _parse_payload_to_dict(data) 
        parsed = {"raw_payload": data}

        ds1 = _safe_int_parse(p.get(0), 0)
        parsed['left_door_open'] = bool(ds1 & (1 << 0))
        parsed['right_door_open'] = bool(ds1 & (1 << 1))
        parsed['charge_port_open'] = bool(ds1 & (1 << 2))
        parsed['pilot_present'] = bool(ds1 & (1 << 3))
        parsed['charging'] = bool(ds1 & (1 << 4))
        # bit 5 is always 1
        parsed['hand_brake_applied'] = bool(ds1 & (1 << 6))
        parsed['car_on'] = bool(ds1 & (1 << 7))

        ds2 = _safe_int_parse(p.get(1), 0)
        parsed['car_locked'] = bool(ds2 & (1 << 3))
        parsed['valet_mode_active'] = bool(ds2 & (1 << 4))
        parsed['bonnet_open'] = bool(ds2 & (1 << 6))
        parsed['trunk_open'] = bool(ds2 & (1 << 7))

        parsed['lock_unlock_state'] = p.get(2)

        parsed['temp_pem_c'] = _safe_float_parse(p.get(3))
        parsed['temp_motor_c'] = _safe_float_parse(p.get(4))
        parsed['temp_battery_c'] = _safe_float_parse(p.get(5))

        parsed['trip_meter_10th_unit'] = _safe_int_parse(p.get(6))
        parsed['odometer_10th_unit'] = _safe_int_parse(p.get(7))
        parsed['speed_dph'] = _safe_float_parse(p.get(8))
        parsed['parking_timer_seconds'] = _safe_int_parse(p.get(9))
        parsed['temp_ambient_c'] = _safe_float_parse(p.get(10))
        
        ds3 = _safe_int_parse(p.get(11), 0)
        parsed['car_awake'] = bool(ds3 & (1 << 0))
        parsed['cooling_pump_on'] = bool(ds3 & (1 << 1))

        parsed['motor_controller_logged_in'] = bool(ds3 & (1 << 6))
        parsed['motor_controller_config_mode'] = bool(ds3 & (1 << 7))
        
        parsed['stale_temps_pem_motor_batt_indicator'] = p.get(12)
        parsed['stale_ambient_temp_indicator'] = p.get(13)
        parsed['vehicle_12v_line_voltage'] = _safe_float_parse(p.get(14))
        
        ds4 = _safe_int_parse(p.get(15), 0)
        parsed['alarm_sounding'] = bool(ds4 & (1 << 2))
        
        parsed['reference_voltage_12v'] = _safe_float_parse(p.get(16))
        
        ds5 = _safe_int_parse(p.get(17), 0)
        parsed['rear_left_door_open'] = bool(ds5 & (1 << 0))
        parsed['rear_right_door_open'] = bool(ds5 & (1 << 1))
        parsed['frunk_open'] = bool(ds5 & (1 << 2))

        parsed['battery_12v_charging'] = bool(ds5 & (1 << 4))
        parsed['aux_12v_systems_online'] = bool(ds5 & (1 << 5))

        parsed['hvac_running'] = bool(ds5 & (1 << 7))

        parsed['temp_charger_c'] = _safe_float_parse(p.get(18))
        parsed['vehicle_12v_current'] = _safe_float_parse(p.get(19))
        parsed['temp_cabin_c'] = _safe_float_parse(p.get(20))
        return parsed

class FirmwareMessageData(ProtocolDataBase):
    ovms_firmware_version: Optional[str] = None
    vin: Optional[str] = None
    network_signal_quality: Optional[str] = None
    write_enabled_firmware: Optional[int] = None # 0=read-only, 1=write-enabled
    vehicle_type_code: Optional[str] = None
    network_name: Optional[str] = None
    distance_to_service_km: Optional[int] = None
    time_to_service_seconds: Optional[int] = None
    ovms_hardware_version: Optional[str] = None
    cellular_connection_mode_status: Optional[str] = None # e.g., "LTE,Online"

    @model_validator(mode='before')
    @classmethod
    def parse_f_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("FirmwareMessageData expects a string payload")
        payload_dict = _parse_payload_to_dict(data)
        parsed = {"raw_payload": data}
        parsed['ovms_firmware_version'] = payload_dict.get(0)
        parsed['vin'] = payload_dict.get(1)
        parsed['network_signal_quality'] = payload_dict.get(2)
        parsed['write_enabled_firmware'] = _safe_int_parse(payload_dict.get(3))
        parsed['vehicle_type_code'] = payload_dict.get(4)
        parsed['network_name'] = payload_dict.get(5)
        parsed['distance_to_service_km'] = _safe_int_parse(payload_dict.get(6))
        parsed['time_to_service_seconds'] = _safe_int_parse(payload_dict.get(7))
        parsed['ovms_hardware_version'] = payload_dict.get(8)
        parsed['cellular_connection_mode_status'] = payload_dict.get(9)
        return parsed

class ExportPowerMessageData(ProtocolDataBase):
    export_power_kw: Optional[float] = None
    export_energy_kwh: Optional[float] = None
    export_duration_s: Optional[int] = None
    export_state_numeric: Optional[int] = None
    export_mode_numeric: Optional[int] = None

    @model_validator(mode='before')
    @classmethod
    def parse_x_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("ExportPowerMessageData expects a string payload")
        
        payload_dict = _parse_payload_to_dict(data)
        parsed = {"raw_payload": data}
        
        parsed['export_power_kw'] = _safe_float_parse(payload_dict.get(0))
        parsed['export_energy_kwh'] = _safe_float_parse(payload_dict.get(1))
        parsed['export_duration_s'] = _safe_int_parse(payload_dict.get(2))
        parsed['export_state_numeric'] = _safe_int_parse(payload_dict.get(3))
        parsed['export_mode_numeric'] = _safe_int_parse(payload_dict.get(4))
        return parsed

class CommandResponseMessageData(ProtocolDataBase):
    command_code: int
    result_code: int # 0=ok, 1=failed, 2=unsupported, 3=unimplemented
    parameters: List[str] = [] # Remaining parts of the payload

    @model_validator(mode='before')
    @classmethod
    def parse_c_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("CommandResponseMessageData expects a string payload")
        
        parts = data.split(',', 2) 
        parsed = {"raw_payload": data}
        if len(parts) >= 2:
            parsed['command_code'] = _safe_int_parse(parts[0], -1) 
            parsed['result_code'] = _safe_int_parse(parts[1], -1)
            if len(parts) > 2 and parts[2]:
                parsed['parameters'] = [param.strip() for param in parts[2].split(',')]
            else:
                parsed['parameters'] = []
        else: 
            parsed['command_code'] = -1
            parsed['result_code'] = -1
            parsed['parameters'] = []
        return parsed

class AppCommandMessageData(ProtocolDataBase):
    command_code: int
    arguments: List[str] = []

    @model_validator(mode='before')
    @classmethod
    def parse_C_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("AppCommandMessageData expects a string payload")
        
        parts = data.split(',', 1)
        parsed = {"raw_payload": data}
        parsed['command_code'] = _safe_int_parse(parts[0], -1)
        if len(parts) > 1 and parts[1]:
            parsed['arguments'] = [arg.strip() for arg in parts[1].split(',')]
        else:
            parsed['arguments'] = []
        return parsed

class PushSubscriptionData(ProtocolDataBase):
    app_id: Optional[str] = None
    push_type: Optional[str] = None 
    push_key_type: Optional[str] = None 
    vehicle_id: Optional[str] = None
    net_pass: Optional[str] = None 
    push_key_value: Optional[str] = None 

    @model_validator(mode='before')
    @classmethod
    def parse_p_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("PushSubscriptionData expects a string payload")
        
        parts = data.split(',', 5)
        parsed = {"raw_payload": data}
        if len(parts) == 6:
            parsed['app_id'] = parts[0]
            parsed['push_type'] = parts[1]
            parsed['push_key_type'] = parts[2]
            parsed['vehicle_id'] = parts[3]
            parsed['net_pass'] = parts[4]
            parsed['push_key_value'] = parts[5]
        return parsed

class HistoricalDataMessage(ProtocolDataBase):
    ackcode: str
    timediff_seconds: int
    record_type: str
    record_number: int
    lifetime_seconds: int
    data_blob: str

    @model_validator(mode='before')
    @classmethod
    def parse_h_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("HistoricalDataMessage expects a string payload")

        # Split into 6 parts: ackcode, timediff, type, num, lifetime, and the rest is data
        parts = data.split(',', 5)
        parsed = {"raw_payload": data}
        if len(parts) == 6:
            parsed['ackcode'] = parts[0]
            parsed['timediff_seconds'] = _safe_int_parse(parts[1], 0)
            parsed['record_type'] = parts[2]
            parsed['record_number'] = _safe_int_parse(parts[3], -1)
            parsed['lifetime_seconds'] = _safe_int_parse(parts[4], 0)
            parsed['data_blob'] = parts[5]
        else:
            logger.warning(f"Malformed historical data (h) payload: expected 6 parts after split, got {len(parts)}. Payload: {data[:100]}")
            # Provide defaults so the model can be created, but the ackcode will be empty.
            # This will be caught by the handler.
            parsed['ackcode'] = ""
            parsed['timediff_seconds'] = 0
            parsed['record_type'] = "MALFORMED"
            parsed['record_number'] = -1
            parsed['lifetime_seconds'] = 0
            parsed['data_blob'] = data

        return parsed

class HistoricalDataMessageH(ProtocolDataBase):
    """Parser for message 'H' (uppercase) - Historical data without acknowledgment.
    Format: recordtype,recordnumber,lifetime,data (4 fields)
    """
    record_type: str
    record_number: int
    lifetime_seconds: int
    data_blob: str

    @model_validator(mode='before')
    @classmethod
    def parse_H_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("HistoricalDataMessageH expects a string payload")

        # Split into 4 parts: recordtype, recordnumber, lifetime, and the rest is data
        parts = data.split(',', 3)
        parsed = {"raw_payload": data}
        if len(parts) == 4:
            parsed['record_type'] = parts[0]
            parsed['record_number'] = _safe_int_parse(parts[1], -1)
            parsed['lifetime_seconds'] = _safe_int_parse(parts[2], 0)
            parsed['data_blob'] = parts[3]
        else:
            logger.warning(f"Malformed historical data (H) payload: expected 4 parts after split, got {len(parts)}. Payload: {data[:100]}")
            # Provide defaults
            parsed['record_type'] = "MALFORMED"
            parsed['record_number'] = -1
            parsed['lifetime_seconds'] = 0
            parsed['data_blob'] = data

        return parsed

class TPMSWheelReading(BaseModel): 
    name: Optional[str] = None
    pressure_kpa: Optional[float] = None
    temperature_c: Optional[float] = None
    health_pct: Optional[float] = None
    alert_level: Optional[int] = None

class TPMSMessageDataY(ProtocolDataBase):
    wheel_readings: List[TPMSWheelReading] = []
    pressures_valid: Optional[bool] = None
    temperatures_valid: Optional[bool] = None
    health_states_valid: Optional[bool] = None
    alert_levels_valid: Optional[bool] = None

    @model_validator(mode='before')
    @classmethod
    def parse_y_payload(cls, data: Any) -> Dict[str, Any]:
        if not isinstance(data, str):
            raise ValueError("TPMSMessageDataY expects a string payload")
        
        parts = data.split(',')
        parsed_dict: Dict[str, Any] = {"raw_payload": data, "wheel_readings": []}
        current_idx = 0
        max_items_per_section = 64

        def parse_validity_flag(value_str: Optional[str]) -> Optional[bool]:
            if value_str is None: return None
            val = _safe_int_parse(value_str, -2) 
            if val == 1: return True
            if val == 0: return False
            return None 

        def parse_bounded_count(value_str: Optional[str], section_name: str) -> int:
            count = _safe_int_parse(value_str, 0)
            if count <= 0:
                return 0
            remaining_parts = max(0, len(parts) - current_idx)
            bounded_count = min(count, remaining_parts, max_items_per_section)
            if bounded_count != count:
                logger.warning(
                    f"Capped TPMS {section_name} count from {count} to {bounded_count} "
                    f"(remaining_parts={remaining_parts}, max_items={max_items_per_section})"
                )
            return bounded_count

        try:
            # Names
            n_names = parse_bounded_count(parts[current_idx] if current_idx < len(parts) else None, "names"); current_idx += 1
            names = [parts[i] for i in range(current_idx, current_idx + n_names) if i < len(parts)]; current_idx += n_names
            
            temp_readings_map: Dict[str, Dict[str, Any]] = {name: {"name": name} for name in names}

            # Pressures
            n_press = parse_bounded_count(parts[current_idx] if current_idx < len(parts) else None, "pressures"); current_idx += 1
            pressures_kpa = [_safe_float_parse(parts[i] if i < len(parts) else None) for i in range(current_idx, current_idx + n_press)]; current_idx += n_press
            parsed_dict['pressures_valid'] = parse_validity_flag(parts[current_idx] if current_idx < len(parts) else None); current_idx += 1
            for i, name in enumerate(names):
                if i < len(pressures_kpa) and name in temp_readings_map: temp_readings_map[name]['pressure_kpa'] = pressures_kpa[i]

            # Temperatures
            n_temps = parse_bounded_count(parts[current_idx] if current_idx < len(parts) else None, "temperatures"); current_idx += 1
            temperatures_c = [_safe_float_parse(parts[i] if i < len(parts) else None) for i in range(current_idx, current_idx + n_temps)]; current_idx += n_temps
            parsed_dict['temperatures_valid'] = parse_validity_flag(parts[current_idx] if current_idx < len(parts) else None); current_idx += 1
            for i, name in enumerate(names):
                if i < len(temperatures_c) and name in temp_readings_map: temp_readings_map[name]['temperature_c'] = temperatures_c[i]

            # Health States
            n_health = parse_bounded_count(parts[current_idx] if current_idx < len(parts) else None, "health_states"); current_idx += 1
            health_states_pct = [_safe_float_parse(parts[i] if i < len(parts) else None) for i in range(current_idx, current_idx + n_health)]; current_idx += n_health
            parsed_dict['health_states_valid'] = parse_validity_flag(parts[current_idx] if current_idx < len(parts) else None); current_idx += 1
            for i, name in enumerate(names):
                if i < len(health_states_pct) and name in temp_readings_map: temp_readings_map[name]['health_pct'] = health_states_pct[i]

            # Alert Levels
            n_alerts = parse_bounded_count(parts[current_idx] if current_idx < len(parts) else None, "alert_levels"); current_idx += 1
            alert_levels = [_safe_int_parse(parts[i] if i < len(parts) else None) for i in range(current_idx, current_idx + n_alerts)]; current_idx += n_alerts
            parsed_dict['alert_levels_valid'] = parse_validity_flag(parts[current_idx] if current_idx < len(parts) else None); current_idx += 1
            for i, name in enumerate(names):
                if i < len(alert_levels) and name in temp_readings_map: temp_readings_map[name]['alert_level'] = alert_levels[i]
            
            parsed_dict['wheel_readings'] = [TPMSWheelReading(**reading) for reading in temp_readings_map.values()]

        except IndexError:
            logger.warning(f"IndexError parsing Y payload '{data[:50]}...'. Incomplete data. Current index: {current_idx}, Parts len: {len(parts)}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Y payload '{data[:50]}...': {e}", exc_info=True)

        return parsed_dict

MESSAGE_PARSERS: Dict[str, Any] = {
    'S': StatusMessageData,
    'L': LocationMessageData,
    'D': EnvironmentMessageData,
    'F': FirmwareMessageData,
    'X': ExportPowerMessageData,
    'c': CommandResponseMessageData,
    'C': AppCommandMessageData,
    'p': PushSubscriptionData,
    'h': HistoricalDataMessage,
    'H': HistoricalDataMessageH,  # Use separate parser for uppercase H (4 fields, no ack)
    'Y': TPMSMessageDataY,
}

def parse_protocol_message_payload(code_char: str, payload_str: str) -> Any:
    parser_model = MESSAGE_PARSERS.get(code_char)
    if parser_model:
        try:
            return parser_model.model_validate(payload_str)
        except ValidationError as e:
            logger.error(f"Pydantic validation error parsing '{code_char}' payload '{payload_str[:50]}...': {e}")
            return ProtocolDataBase(raw_payload=payload_str) # Fallback to base model with raw payload
        except Exception as e:
            logger.error(f"Generic error parsing '{code_char}' payload '{payload_str[:50]}...': {e}")
            return ProtocolDataBase(raw_payload=payload_str) # Fallback
    return payload_str
