"""
Field definitions for known OVMS history record types (data notifications).

The delivery channel (notify/data/...) is generic OVMS framework; the record layout is a
convention of the sending vehicle module. Types listed here get named table columns and
optionally trend charts in the data log browser - unknown types fall back to generic
F1..Fn columns, so this registry is purely additive.

Field indexes are 0-based positions within the DATA part of a record, i.e. after the
"<type>,<recno>,<lifetime>" header - matching the data_payload stored in historical_data.

Chart entries are deliberately one measure per chart (single axis). Colors are fixed per
measure (dark-surface palette steps).
"""

_BLUE = "#3987e5"
_AQUA = "#199e70"

DATALOG_DEFINITIONS = {

    # Framework standard: trip summary, sent on vehicle on/off.
    # Enable on the module: config set notify log.trip.storetime <days>
    "*-LOG-Trip": {
        "description": "Trip summary log (framework standard, sent at ignition on/off)",
        "fields": [
            "GPS lock", "Latitude", "Longitude", "Altitude [m]", "Location",
            "Odometer", "Trip [km]", "Drive time [s]", "Drive mode",
            "SOC [%]", "Range est [km]", "Range ideal [km]", "Range full [km]",
            "Energy used [kWh]", "Energy recd [kWh]", "Coulomb used [Ah]", "Coulomb recd [Ah]",
            "SOH [%]", "Battery health", "CAC [Ah]",
            "Energy used total [kWh]", "Energy recd total [kWh]",
            "Coulomb used total [Ah]", "Coulomb recd total [Ah]",
            "Ambient [°C]", "Cabin [°C]", "Battery [°C]", "Inverter [°C]", "Motor [°C]", "12V charger [°C]",
            "TPMS temp min [°C]", "TPMS temp max [°C]", "TPMS press min [kPa]", "TPMS press max [kPa]",
            "TPMS health min [%]", "TPMS health max [%]",
        ],
        "charts": [
            {"title": "SOH over time", "label": "SOH [%]", "index": 17, "color": _BLUE},
            {"title": "Usable capacity (CAC) over time", "label": "CAC [Ah]", "index": 19, "color": _AQUA},
        ],
    },

    # Framework standard: charge/generator session, sent at the end of a charge.
    # Enable on the module: config set notify log.grid.storetime <days>
    "*-LOG-Grid": {
        "description": "Charge/generator session log (framework standard, sent at end of charge)",
        "fields": [
            "GPS lock", "Latitude", "Longitude", "Altitude [m]", "Location",
            "Charge type", "Charge state", "Charge substate", "Charge mode",
            "Current limit [A]", "Range limit [km]", "SOC limit [%]",
            "Gen type", "Gen state", "Gen substate", "Gen mode",
            "Gen current limit [A]", "Gen range limit [km]", "Gen SOC limit [%]",
            "Charge time [s]", "Charged [kWh]", "Grid [kWh]", "Grid total [kWh]",
            "Gen time [s]", "Gen [kWh]", "Gen grid [kWh]", "Gen grid total [kWh]",
            "SOC [%]", "Range est [km]", "Range ideal [km]", "Range full [km]",
            "Battery [V]", "Battery [°C]",
            "Charger [°C]", "12V charger [°C]", "Ambient [°C]", "Cabin [°C]",
            "SOH [%]", "Battery health", "CAC [Ah]",
            "Energy used total [kWh]", "Energy recd total [kWh]",
            "Coulomb used total [Ah]", "Coulomb recd total [Ah]",
            "Odometer",
        ],
        "charts": [
            {"title": "Charged energy per session", "label": "Charged [kWh]", "index": 20, "color": _BLUE},
            {"title": "SOH over time", "label": "SOH [%]", "index": 37, "color": _AQUA},
        ],
    },

    # VW e-Up: battery capacity measured per charge.
    # Enable on the module: config set xvu log.chargecap.storetime <days>
    "XVU-LOG-ChargeCap": {
        "description": "VW e-Up: battery capacity measured during a charge",
        "fields": [
            "Charge time [s]", "Battery [°C]", "Energy range [kWh]",
            "SOC norm start [%]", "SOC norm diff [%]", "SOC abs start [%]", "SOC abs diff [%]",
            "Energy charged [kWh]", "Coulomb charged [Ah]",
            "Cap norm [Ah]", "Cap abs [Ah]", "Cap norm [kWh]", "Cap abs [kWh]",
        ],
        "charts": [
            {"title": "Measured capacity per charge", "label": "Cap abs [Ah]", "index": 10, "color": _BLUE},
        ],
    },

    # VW e-Up: smoothed SOH derived from the capacity measurements.
    "XVU-LOG-ChargeCapSOH": {
        "description": "VW e-Up: SOH derived from the smoothed capacity measurements",
        "fields": [
            "CAC old [Ah]", "CAC new [Ah]", "SOH old [%]", "SOH new [%]",
            "Cap norm [Ah]", "Cap abs [Ah]", "Cap norm [kWh]", "Cap abs [kWh]",
        ],
        "charts": [
            {"title": "SOH over time", "label": "SOH new [%]", "index": 3, "color": _BLUE},
            {"title": "Usable capacity (CAC) over time", "label": "CAC new [Ah]", "index": 1, "color": _AQUA},
        ],
    },

    # NIU GT EVO: buffered GPS track log. Blocklisted from storage by default
    # (Karto consumes it) - the definition is here in case the blocklist is changed.
    "XNE-GPS-Log": {
        "description": "NIU GT EVO: buffered GPS track log (normally consumed by Karto)",
        "fields": [
            "Latitude", "Longitude", "GPS speed [km/h]", "Course [°]", "HDOP",
            "Satellites", "Speed [km/h]", "Odometer [km]", "SOC [%]",
        ],
        "charts": [],
    },
}
